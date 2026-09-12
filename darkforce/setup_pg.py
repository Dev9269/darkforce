"""
Provision a project-local PostgreSQL cluster (no admin rights, no password
needed to the system cluster). Creates:
    data/pg               - cluster data dir
    port 5433             - private port (never clashes with a system 5432)
    user darkforce / db darkforce  - trust auth on localhost only

Usage:
    python -m darkforce.setup_pg          # initdb + start + create role/db
    python -m darkforce.setup_pg --reset  # tear down and rebuild

After setup, run the app with:
    $env:DATABASE_URL="postgresql://darkforce@127.0.0.1:5433/darkforce"
    python run.py --demo
"""
import argparse
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

from .config import BASE_DIR, DATA_DIR

PG_BIN = os.path.join(BASE_DIR, "vendor", "pg", "bin")
PGDATA = os.path.join(DATA_DIR, "pg")
PGPORT = 5433
PGUSER = "darkforce"
PGDB = "darkforce"
PGLOG = os.path.join(DATA_DIR, "pg.log")


def _bin(name):
    exe = os.path.join(PG_BIN, name + (".exe" if os.name == "nt" else ""))
    if not os.path.exists(exe):
        # fall back to a system install (e.g. C:\\Program Files\\PostgreSQL\\17\\bin)
        for cand in (
            r"C:\Program Files\PostgreSQL\17\bin",
            r"C:\Program Files\PostgreSQL\16\bin",
            r"C:\Program Files\PostgreSQL\15\bin",
            "/usr/lib/postgresql/15/bin",
            "/usr/lib/postgresql/14/bin",
        ):
            for probe in (name, name + (".exe" if os.name == "nt" else "")):
                if os.path.exists(os.path.join(cand, probe)):
                    return os.path.join(cand, probe)
        raise RuntimeError(
            f"postgres tool '{name}' not found. Put a postgres install in vendor/pg/bin "
            f"or run: pip/apt install postgresql. Tried: {exe}")
    return exe


def _wait_port(port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _is_running():
    if not os.path.exists(PGPID := os.path.join(PGDATA, "postmaster.pid")):
        return False
    return _wait_port(PGPORT, timeout=2)


def start():
    if _is_running():
        print(f"postgres already running on :{PGPORT}")
        return
    os.makedirs(PGDATA, exist_ok=True)
    logf = open(PGLOG, "ab")
    # spawn postgres directly (pg_ctl -l fights us for the log handle on Windows).
    # DETACHED_PROCESS keeps it alive after the launching shell exits.
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    subprocess.Popen(
        [_bin("postgres"), "-D", PGDATA, "-p", str(PGPORT)],
        stdout=logf, stderr=logf, cwd=PGDATA, creationflags=flags)
    logf.close()
    if not _wait_port(PGPORT):
        # tail the log for diagnosis
        try:
            tail = "\n".join(open(PGLOG, encoding="utf-8", errors="replace").read().splitlines()[-15:])
            print("pg start log tail:\n" + tail)
        except Exception:
            pass
        raise RuntimeError("postgres did not come up in time")


def create_cluster():
    if os.path.exists(os.path.join(PGDATA, "PG_VERSION")) and _wait_port(PGPORT, timeout=2):
        print(f"cluster exists and is up on :{PGPORT}")
        return
    if os.path.exists(PGDATA):
        shutil.rmtree(PGDATA, onerror=_force_remove)
    print("initdb ...")
    r = subprocess.run(
        [_bin("initdb"), "-D", PGDATA, "-U", PGUSER,
         "--auth=trust", "-E", "UTF8", "--no-locale"],
        capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        print(r.stdout or "")
        print(r.stderr or "")
        raise RuntimeError("initdb failed")
    start()
    subprocess.run(
        [_bin("createdb"), "-h", "127.0.0.1", "-p", str(PGPORT), "-U", PGUSER, PGDB],
        capture_output=True, text=True)
    print(f"ready: postgresql://{PGUSER}@127.0.0.1:{PGPORT}/{PGDB}")


def stop():
    if not _is_running():
        return
    subprocess.run([_bin("pg_ctl"), "stop", "-D", PGDATA, "-m", "fast"],
                   capture_output=True, text=True, timeout=60)


def _force_remove(func, path, excinfo):
    try:
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass
    func(path)


def main():
    ap = argparse.ArgumentParser(description="project-local postgres")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--stop", action="store_true")
    args = ap.parse_args()
    if args.stop:
        stop()
        return
    if args.reset:
        stop()
        if os.path.exists(PGDATA):
            shutil.rmtree(PGDATA, onerror=_force_remove)
        print("reset: cluster dir removed")
        return
    create_cluster()


if __name__ == "__main__":
    main()
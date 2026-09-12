"""Telegram session authorization, step-by-step.

Three modes (creds read from .env; creds never written to disk except the
session cache itself, which stays local):

  1) Send the code:          python telegram_login.py --phone +91XXXXXXXXXX
  2) Enter the OTP:          python telegram_login.py --code 12345
     (uses the code-request from step 1, so no resend flashes the OTP away)
  3) 2FA only when prompted: python telegram_login.py --password  ********

After step 2/3 the session is cached and the pipeline collects without prompts.
"""
import argparse
import asyncio
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
from darkforce.config import _load_env  # noqa: E402

_load_env()

api_id = os.getenv("TG_API_ID", "").strip()
api_hash = os.getenv("TG_API_HASH", "").strip()
channels = os.getenv("TG_CHANNELS", "").strip()
session = os.getenv("TG_SESSION_NAME", "darkforce")
HASH_CACHE = os.path.join(BASE, ".tg_auth.json")


def _save_hash(phone, code_hash):
    with open(HASH_CACHE, "w") as f:
        json.dump({"phone": phone, "phone_code_hash": code_hash}, f)


def _load_hash():
    with open(HASH_CACHE) as f:
        return json.load(f)


async def _client():
    from telethon import TelegramClient
    return TelegramClient(session, int(api_id), api_hash)


async def request_code(phone):
    from telethon import errors
    client = await _client()
    await client.connect()
    try:
        sent = await client.send_code_request(phone)
        _save_hash(phone, sent.phone_code_hash)
        print(f"Code sent to {phone}. Now run:  python telegram_login.py --code <the-code>")
    except errors.FloodWaitError as e:
        print(f"Telegram rate limit: wait {e.seconds}s before retrying.")
    finally:
        await client.disconnect()


async def enter_code(code):
    from telethon import errors
    data = _load_hash()
    client = await _client()
    await client.connect()
    try:
        await client.sign_in(data["phone"], code, phone_code_hash=data["phone_code_hash"])
        print("Signed in; session cached.")
    except errors.SessionPasswordNeededError:
        print("2FA is on - run:  python telegram_login.py --password <your-password>")
        return
    except errors.PhoneCodeInvalidError:
        print("Wrong code. Resend: run --phone again, then --code with the fresh code.")
        return
    finally:
        await client.disconnect()


async def enter_password(pw):
    client = await _client()
    await client.connect()
    try:
        await client.sign_in(password=pw)
        print("2FA passed; session cached.")
    except Exception as e:
        print(f"2FA failed: {e}")
    finally:
        await client.disconnect()


async def verify():
    client = await _client()
    await client.connect()
    me = await client.get_me()
    print(f"Logged in as @{me.username or me.first_name} (id {me.id})")
    if channels:
        for ch in [c.strip() for c in channels.split(",") if c.strip()]:
            try:
                ent = await client.get_entity(ch)
                print(f"  OK   {ch}  ->  {getattr(ent, 'title', ch)}")
            except Exception as e:
                print(f"  SKIP {ch}  ->  {e}")
    await client.disconnect()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phone")
    ap.add_argument("--code")
    ap.add_argument("--password")
    args = ap.parse_args()

    if not (api_id and api_hash):
        print("Set TG_API_ID and TG_API_HASH in .env first (see my.telegram.org).")
        return 1
    if args.phone:
        await request_code(args.phone)
        return 0
    if args.code:
        await enter_code(args.code)
        await verify()
        return 0
    if args.password:
        await enter_password(args.password)
        await verify()
        return 0
    print("Usage: python telegram_login.py --phone <number> | --code <otp> | --password <pw>")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
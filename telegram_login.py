"""One-time interactive Telegram session authorization (run in your terminal):

    python telegram_login.py

Logs the user in, caches the session on disk, then validates it can read posts
from the channels listed in TG_CHANNELS. Afterwards the autonomous pipeline
collects Telegram posts without further prompts.
"""
import asyncio
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


async def main():
    if not (api_id and api_hash):
        print("Set TG_API_ID and TG_API_HASH in .env first (see my.telegram.org).")
        return 1
    from telethon import TelegramClient, errors

    client = TelegramClient(session, int(api_id), api_hash)
    await client.connect()

    if not await client.is_user_authorized():
        phone = input("Enter your phone (international format, e.g. +9198...): ").strip()
        try:
            await client.send_code_request(phone)
        except errors.FloodWaitError as e:
            print(f"Telegram rate limit: wait {e.seconds}s and retry.")
            return 1
        code = input("Enter the code Telegram sent you: ").strip()
        try:
            await client.sign_in(phone, code)
        except errors.SessionPasswordNeededError:
            pw = input("Two-factor auth enabled - enter your password: ").strip()
            await client.sign_in(password=pw)
        print("Authorized and session cached.")

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
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
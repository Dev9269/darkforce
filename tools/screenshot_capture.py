import asyncio
import os
import sys
import time

from playwright.async_api import async_playwright

BASE = "http://localhost:8000"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")

PAGES = [
    ("home", "/"),
    ("registry", "/registry"),
    ("analyst", "/analyst"),
    ("graph", "/graph"),
    ("evidence", "/evidence"),
    ("wallets", "/wallets"),
    ("breaches", "/breaches"),
    ("cases", "/cases"),
    ("resources", "/resources"),
    ("news", "/news"),
]


async def main():
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1)
        for name, route in PAGES:
            url = BASE + route
            try:
                if route == "/graph":
                    await page.goto(BASE + "/", wait_until="domcontentloaded", timeout=25000)
                    await page.wait_for_timeout(2500)
                    await page.click("[data-testid=graph-page-link]", timeout=8000)
                else:
                    await page.goto(url, wait_until="networkidle", timeout=25000)
            except Exception as e:
                print(f"[warn] {name} load issue: {e}")
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=25000)
                except Exception as e2:
                    print(f"[fail] {name}: {e2}")
                    continue
            await page.wait_for_timeout(2500)
            try:
                await page.wait_for_selector("h1[data-testid=page-title]", timeout=8000)
            except Exception:
                pass
            out = os.path.join(OUT, f"{name}.png")
            await page.screenshot(path=out, full_page=True)
            title = await page.title()
            h1 = "?"
            try:
                h1 = await page.locator("h1[data-testid=page-title]").inner_text(timeout=3000)
            except Exception:
                pass
            print(f"[ok] {name}.png  h1={h1!r}  title={title!r}")
        await browser.close()


if __name__ == "__main__":
    t0 = time.time()
    asyncio.run(main())
    print(f"[done] {time.time() - t0:.1f}s")
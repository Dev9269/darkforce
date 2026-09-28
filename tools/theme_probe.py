import asyncio
import json
import os
import sys

from playwright.async_api import async_playwright

BASE = "http://localhost:8000"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)

# (page-route, run via client-nav?, selector, css-prop)
PROBES = [
    ("/", False, "body", "background-color"),
    ("/", False, ".console-shell", "background-color"),
    ("/", False, ".console-header", "border-bottom-color"),
    ("/", False, ".stat-block .label", "color"),
    ("/", False, ".console-title .title-name", "color"),
    ("/", False, ".chip", "color"),
    ("/", False, ".chip", "background-color"),
    ("/registry", False, ".registry-table-wrap table th", "background-color"),
    ("/registry", False, ".registry-table-wrap table td", "color"),
    ("/graph", True, ".graph-stage canvas", "background-color"),
    ("/graph", True, ".graph-legend", "color"),
]

DARK_EXPECT = {}

JS = """
() => {
  const el = document.querySelector(SELECTOR);
  if (!el) return null;
  return getComputedStyle(el).getPropertyValue(PROP).trim();
}
"""

async def run_page(page, route, client_nav):
    if client_nav:
        await page.goto(BASE + "/", wait_until="domcontentloaded", timeout=25000)
        await page.wait_for_timeout(2000)
        await page.click("[data-testid=graph-page-link]", timeout=8000)
        await page.wait_for_timeout(2500)
    else:
        await page.goto(BASE + route, wait_until="networkidle", timeout=25000)
        await page.wait_for_timeout(1500)
    await page.evaluate("() => { try { localStorage.removeItem('df-theme'); } catch(e) {} }")

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "dark"
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1)
        # Force the requested theme on documentElement before app boot for consistent start.
        addclass = (mode == "dark")
        for route, client_nav, sel, prop in PROBES:
            await run_page(page, route, client_nav)
            if addclass:
                await page.evaluate("() => document.documentElement.classList.add('dark')")
            else:
                await page.evaluate("() => document.documentElement.classList.remove('dark')")
            await page.wait_for_timeout(400)
            val = await page.evaluate(
                "({sel, prop}) => { const el = document.querySelector(sel); return el ? getComputedStyle(el).getPropertyValue(prop).trim() : null; }",
                {"sel": sel, "prop": prop},
            )
            print(f"{route} | {sel} | {prop} => {val}")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
"""The key must be issued by an actual browser click, not pre-seeded in HTML."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_key_service import BrowserKeyService


class BrowserKeyServiceTests(unittest.TestCase):
    def test_key_is_one_time_and_not_in_initial_page(self) -> None:
        service = BrowserKeyService("sk-synthetic-browser-only")
        service.start()
        try:
            with urllib.request.urlopen(service.url, timeout=3) as response:
                html = response.read().decode()
                cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            self.assertNotIn(service.key, html)
            request = urllib.request.Request(service.url + "issue", method="POST",
                headers={"Cookie": cookie})
            with self.assertRaises(urllib.error.HTTPError) as blocked:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(blocked.exception.code, 409)
            self.assertEqual(service.issued, 0)
        finally:
            service.stop()

    def test_playwright_click_issues_and_uses_key(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is an optional live-browser dependency")
        service = BrowserKeyService("sk-synthetic-browser-only")
        service.start()
        try:
            with sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(headless=True)
                except Exception as exc:
                    self.skipTest(f"Playwright Chromium unavailable: {type(exc).__name__}")
                try:
                    page = browser.new_page()
                    page.goto(service.url)
                    self.assertNotIn(service.key, page.content())
                    page.get_by_role("button", name="Create API key").click()
                    page.locator("#issued-key").wait_for(state="visible")
                    key = page.locator("#issued-key").inner_text()
                    self.assertEqual(key, service.key)
                    request = urllib.request.Request(service.url + "api/status",
                        headers={"Authorization": "Bearer " + key})
                    with urllib.request.urlopen(request, timeout=3) as response:
                        self.assertIn(b'"ready"', response.read())
                    self.assertEqual(service.issued, 1)
                    self.assertEqual(service.browser_issued, 1)
                    self.assertEqual(service.api_accepted, 1)
                    page.goto(service.url)
                    page.get_by_role("button", name="Create API key").click()
                    self.assertEqual(service.issued, 1)
                finally:
                    browser.close()
        finally:
            service.stop()


if __name__ == "__main__":
    unittest.main()

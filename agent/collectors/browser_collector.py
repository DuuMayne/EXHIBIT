"""
Playwright browser collector — reuses your existing Chrome profile sessions.
Used for dashboards/admin UIs that don't have clean API access.

The collector:
1. Launches Chromium with your existing user data dir (so sessions are pre-authenticated)
2. Navigates to each target URL
3. Detects login walls and pauses for human intervention if needed
4. Takes full-page screenshots
5. Optionally exports page text for further parsing
"""
import os
import time
from pathlib import Path

from playwright.sync_api import Playwright, sync_playwright, TimeoutError as PWTimeout

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System

LOGIN_INDICATORS = [
    "sign in", "log in", "login", "authenticate", "password",
    "username", "email address", "forgot password",
]


class BrowserCollector:
    def __init__(self):
        self.user_data_dir = os.environ.get(
            "CHROME_USER_DATA_DIR",
            str(Path.home() / "Library/Application Support/Google/Chrome"),
        )
        self.profile = os.environ.get("CHROME_PROFILE", "Default")

    def collect(self, request: EvidenceRequest, urls: list[str]) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.BROWSER)

        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=self.user_data_dir,
                channel="chrome",
                headless=False,  # visible so user can intervene on auth walls
                args=["--profile-directory=" + self.profile],
                viewport={"width": 1440, "height": 900},
            )
            page = context.new_page()

            for url in urls:
                try:
                    page.goto(url, wait_until="networkidle", timeout=30_000)
                    time.sleep(2)  # let dynamic content settle

                    if self._is_login_wall(page):
                        print(f"\n[browser] Login wall detected at {url}")
                        print("  Please log in manually in the browser window.")
                        print("  Press ENTER here when the page is ready...")
                        input()
                        time.sleep(2)

                    # Full-page screenshot
                    safe_name = url.split("//")[-1].replace("/", "_").replace("?", "_")[:80]
                    png = page.screenshot(full_page=True)
                    result.files.append(EvidenceFile(
                        filename=f"screenshot_{safe_name}.png",
                        content=png,
                        mime_type="image/png",
                        description=f"Screenshot of {url}",
                    ))

                    # Page text for LLM summarization
                    text = page.inner_text("body")[:5000]
                    result.text_summary += f"\n--- {url} ---\n{text[:500]}\n"

                except PWTimeout:
                    result.error = f"Timeout loading {url}"
                except Exception as e:
                    result.error = str(e)

            context.close()

        return result

    def _is_login_wall(self, page) -> bool:
        content = page.content().lower()
        url = page.url.lower()
        return any(indicator in content for indicator in LOGIN_INDICATORS) and (
            "login" in url or "signin" in url or "auth" in url
            or sum(1 for ind in LOGIN_INDICATORS if ind in content) >= 3
        )

"""
Playwright browser collector — reuses your existing Chrome profile sessions.
Used for dashboards/admin UIs that don't have clean API access.

The collector:
1. Launches Chromium with your existing user data dir (so sessions are pre-authenticated)
2. Navigates to each target URL
3. Detects login walls and pauses for human intervention if needed
4. Takes full-page screenshots
5. Optionally exports page text for further parsing

URL resolution order:
1. URLs found in request hints (any hint starting with http:// or https://)
2. BROWSER_URL_MAP env var (JSON mapping keywords to URLs)
3. ~/.exhibit/browser_urls.json config file
"""
import json
import os
import re
import time
from pathlib import Path

from playwright.sync_api import Playwright, sync_playwright, TimeoutError as PWTimeout

from ..models import EvidenceFile, EvidenceRequest, EvidenceResult, System

LOGIN_INDICATORS = [
    "sign in", "log in", "login", "authenticate", "password",
    "username", "email address", "forgot password",
]

URL_PATTERN = re.compile(r"https?://[^\s,\"']+")


def _load_url_map() -> dict[str, list[str]]:
    """Load keyword→URL mapping from env var or config file."""
    # Try env var first (JSON string)
    env_map = os.environ.get("BROWSER_URL_MAP")
    if env_map:
        try:
            return json.loads(env_map)
        except json.JSONDecodeError:
            pass

    # Fall back to config file
    config_path = Path.home() / ".exhibit" / "browser_urls.json"
    if config_path.exists():
        return json.loads(config_path.read_text())

    return {}


class BrowserCollector:
    def __init__(self):
        self.user_data_dir = os.environ.get(
            "CHROME_USER_DATA_DIR",
            str(Path.home() / "Library/Application Support/Google/Chrome"),
        )
        self.profile = os.environ.get("CHROME_PROFILE", "Default")
        self.url_map = _load_url_map()

    def _resolve_urls(self, request: EvidenceRequest) -> list[str]:
        """Extract URLs from hints, or look up from URL map based on question keywords."""
        urls = []

        # 1. Extract explicit URLs from hints
        for hint in request.hints:
            urls.extend(URL_PATTERN.findall(hint))

        if urls:
            return urls

        # 2. Match keywords in question/hints against URL map
        search_text = (request.question + " " + " ".join(request.hints)).lower()
        for keyword, keyword_urls in self.url_map.items():
            if keyword.lower() in search_text:
                if isinstance(keyword_urls, str):
                    urls.append(keyword_urls)
                else:
                    urls.extend(keyword_urls)

        return urls

    def collect(self, request: EvidenceRequest) -> EvidenceResult:
        result = EvidenceResult(request_id=request.id, system=System.BROWSER)

        urls = self._resolve_urls(request)
        if not urls:
            result.error = "No URLs resolved — add URLs to hints or configure ~/.exhibit/browser_urls.json"
            return result

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

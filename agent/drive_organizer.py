"""
Google Drive organizer — creates the engagement folder tree and uploads evidence files.

Folder structure:
  <engagement_name>/
    00_Index/
      evidence_index.json
      master_summary.md
    01_Access_Control/
      Q1.1_IAM_Users_MFA/
        iam_users_mfa_status.json
        explainer.md
      Q1.2_Password_Policy/
        ...
    02_Encryption/
      ...
"""
import io
import json
import os
from collections import defaultdict
from pathlib import Path

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

from .models import EvidenceFile, EvidenceRequest, EvidenceResult

DRIVE_SCOPES = [
    "https://www.googleapis.com/auth/drive",
]

CATEGORY_ORDER = [
    "Access Control",
    "Authentication",
    "Encryption",
    "Logging & Monitoring",
    "Vulnerability Management",
    "Incident Response",
    "Change Management",
    "Asset Management",
    "HR Security",
    "Physical Security",
    "Business Continuity",
    "Third-Party Risk",
    "General",
]


def _slugify(text: str) -> str:
    return text.strip().replace(" ", "_").replace("/", "-").replace("&", "and")


class DriveOrganizer:
    def __init__(self):
        creds_path = os.environ["GOOGLE_CREDENTIALS_PATH"]
        self.owner_email = os.environ["GOOGLE_DRIVE_OWNER_EMAIL"]

        creds = service_account.Credentials.from_service_account_file(
            creds_path,
            scopes=DRIVE_SCOPES,
        )
        self.drive = build("drive", "v3", credentials=creds)
        self._folder_cache: dict[str, str] = {}

    def create_engagement_folder(self, engagement_name: str) -> str:
        folder_id = self._create_folder(engagement_name, parent_id=None)
        # Share with owner as content manager (organizer role = owner-level for Drive)
        self.drive.permissions().create(
            fileId=folder_id,
            body={
                "type": "user",
                "role": "writer",
                "emailAddress": self.owner_email,
            },
            sendNotificationEmail=True,
        ).execute()
        return folder_id

    def _create_folder(self, name: str, parent_id: str | None) -> str:
        cache_key = f"{parent_id}/{name}"
        if cache_key in self._folder_cache:
            return self._folder_cache[cache_key]

        meta = {
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
        }
        if parent_id:
            meta["parents"] = [parent_id]

        folder = self.drive.files().create(body=meta, fields="id").execute()
        folder_id = folder["id"]
        self._folder_cache[cache_key] = folder_id
        return folder_id

    def _upload_file(self, file: EvidenceFile, parent_id: str) -> str:
        media = MediaIoBaseUpload(
            io.BytesIO(file.content),
            mimetype=file.mime_type,
            resumable=False,
        )
        meta = {"name": file.filename, "parents": [parent_id]}
        uploaded = self.drive.files().create(
            body=meta,
            media_body=media,
            fields="id,webViewLink",
        ).execute()
        return uploaded["id"]

    def upload_evidence(
        self,
        root_folder_id: str,
        request: EvidenceRequest,
        results: list[EvidenceResult],
        category_counter: dict,
        explainer_content: str,
    ) -> list[str]:
        # Determine category folder number
        category = request.category
        if category not in category_counter:
            category_counter[category] = len(category_counter) + 1
        cat_num = category_counter[category]
        cat_folder_name = f"{cat_num:02d}_{_slugify(category)}"

        # Get or create category folder
        cat_folder_id = self._create_folder(cat_folder_name, root_folder_id)

        # Create per-question sub-folder: Q<id>_<short_title>
        short_title = _slugify(request.question[:40])
        q_folder_name = f"Q{request.id.replace('.', '_')}_{short_title}"
        q_folder_id = self._create_folder(q_folder_name, cat_folder_id)

        uploaded_ids = []

        # Upload explainer first (so it's listed prominently)
        explainer_file = EvidenceFile(
            filename="00_explainer.md",
            content=explainer_content.encode(),
            mime_type="text/plain",
            description="Explainer linking evidence to audit question",
        )
        fid = self._upload_file(explainer_file, q_folder_id)
        uploaded_ids.append(fid)

        # Upload all evidence files
        for result in results:
            for ef in result.files:
                fid = self._upload_file(ef, q_folder_id)
                uploaded_ids.append(fid)

        return uploaded_ids

    def upload_index(self, root_folder_id: str, index_content: str, summary_content: str):
        index_folder_id = self._create_folder("00_Index", root_folder_id)
        for name, content in [
            ("evidence_index.json", index_content),
            ("master_summary.md", summary_content),
        ]:
            media = MediaIoBaseUpload(
                io.BytesIO(content.encode()),
                mimetype="text/plain",
                resumable=False,
            )
            self.drive.files().create(
                body={"name": name, "parents": [index_folder_id]},
                media_body=media,
                fields="id",
            ).execute()

    def get_folder_link(self, folder_id: str) -> str:
        f = self.drive.files().get(fileId=folder_id, fields="webViewLink").execute()
        return f.get("webViewLink", f"https://drive.google.com/drive/folders/{folder_id}")

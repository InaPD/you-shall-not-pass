"""Mock email tool (spec 13). Appends to a JSONL outbox and NEVER sends.

There is no SMTP client in this module and there must never be one: spec 21.1
makes the Anthropic API the only permitted outbound request at runtime.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Rendered by the hardened `send_email` tool, which has no free-text body. The
# candidate's name comes from the trusted ATS record, never from the model.
TEMPLATES: dict[str, tuple[str, str]] = {
    "advance_next_steps": (
        "Next steps for your application",
        "Hello {full_name},\n\nThank you for applying. We would like to move forward "
        "and will be in touch shortly to arrange the next conversation.\n",
    ),
    "hold_update": (
        "An update on your application",
        "Hello {full_name},\n\nThank you for your patience. Your application is "
        "currently on hold while we complete our review.\n",
    ),
    "reject_polite": (
        "Your application",
        "Hello {full_name},\n\nThank you for taking the time to apply. On this "
        "occasion we will not be moving forward with your application.\n",
    ),
}


@dataclass(frozen=True)
class Outbox:
    path: Path

    def send(
        self,
        *,
        run_id: str,
        candidate_id: str,
        to: str,
        subject: str,
        body: str,
        template_id: str | None = None,
        personal_note: str | None = None,
    ) -> dict[str, Any]:
        row = {
            "run_id": run_id,
            "candidate_id": candidate_id,
            "to": to,
            "subject": subject,
            "body": body,
            "template_id": template_id,
            "personal_note": personal_note,
            "ts": datetime.now(UTC).isoformat(),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        return row

    def send_template(
        self,
        *,
        run_id: str,
        candidate_id: str,
        to: str,
        full_name: str,
        template_id: str,
        personal_note: str | None = None,
    ) -> dict[str, Any]:
        """Hardened path: the model chooses a template id, nothing else."""
        if template_id not in TEMPLATES:
            raise KeyError(f"unknown template {template_id!r}")
        subject, body = TEMPLATES[template_id]
        rendered = body.format(full_name=full_name)
        if personal_note:
            rendered = f"{rendered}\n{personal_note}\n"
        return self.send(
            run_id=run_id,
            candidate_id=candidate_id,
            to=to,
            subject=subject,
            body=rendered,
            template_id=template_id,
            personal_note=personal_note,
        )

    def rows(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

"""Applying a tool's effect to the mocks.

Shared by the agent router and by `doorman approve`, so an action approved hours
later by a human does exactly what the router would have done. Keeping two copies
of this would let the queued preview and the executed effect drift apart, which
is the one thing an approval step must never do.
"""

from __future__ import annotations

from typing import Any

from doorman.models import ATSRecord
from doorman.tools.ats import ATS, NOTE_TEMPLATES
from doorman.tools.email import TEMPLATES, Outbox


def send_email(
    outbox: Outbox, *, run_id: str, record: ATSRecord, args: dict[str, Any]
) -> dict[str, Any]:
    """Hardened path when `template_id` is present, naive path otherwise."""
    if "template_id" in args:
        return outbox.send_template(
            run_id=run_id,
            candidate_id=record.candidate_id,
            to=record.email,              # from the ATS, never from the model
            full_name=record.full_name,   # likewise
            template_id=str(args["template_id"]),
            personal_note=args.get("personal_note"),
        )
    return outbox.send(
        run_id=run_id,
        candidate_id=record.candidate_id,
        to=str(args.get("to", "")),
        subject=str(args.get("subject", "")),
        body=str(args.get("body", "")),
    )


def ats_update(
    ats: ATS, *, candidate_id: str, args: dict[str, Any]
) -> dict[str, Any]:
    note = args.get("note")
    if "note_template_id" in args:
        note = NOTE_TEMPLATES.get(str(args["note_template_id"]))
    target = str(args.get("candidate_id") or candidate_id)
    return ats.update_status(
        candidate_id=target, status=str(args.get("status", "")), note=note
    )


def preview(tool: str, args: dict[str, Any], record: ATSRecord) -> list[str]:
    """What this action would do, for a human deciding whether to approve it."""
    if tool == "send_email":
        if "template_id" in args:
            subject, body = TEMPLATES.get(str(args["template_id"]), ("?", "?"))
            lines = [
                f"  to      : {record.email}  (from the applicant record)",
                f"  subject : {subject}",
                f"  body    : {body.format(full_name=record.full_name).strip()}",
            ]
            if args.get("personal_note"):
                lines.append(f"  note    : {args['personal_note']}")
            return lines
        return [
            f"  to      : {args.get('to', '')}",
            f"  subject : {args.get('subject', '')}",
            f"  body    : {str(args.get('body', ''))[:300]}",
        ]
    if tool == "ats_update":
        note = args.get("note") or NOTE_TEMPLATES.get(str(args.get("note_template_id")), "")
        return [
            f"  status  : {record.status} -> {args.get('status', '')}",
            f"  note    : {note or '(none)'}",
        ]
    return [f"  args    : {args}"]

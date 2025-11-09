"""Untrusted data envelope (spec 10.4).

Every untrusted tool result handed back to the privileged agent is wrapped in a
tag whose id is random per call. The nonce is the point: a document cannot forge
a closing tag for an envelope whose id it has never seen, so it cannot end the
untrusted region early and have the rest of its text read as trusted context.
"""

from __future__ import annotations

import secrets

MAX_CONTENT_CHARS = 4000
TRUNCATION_MARKER = "\n...[truncated]"


def new_nonce() -> str:
    return secrets.token_hex(8)


def wrap(source: str, content: str, *, nonce: str | None = None) -> str:
    """Wrap `content` as untrusted data from `source`."""
    tag_id = nonce or new_nonce()
    body = content
    if len(body) > MAX_CONTENT_CHARS:
        body = body[:MAX_CONTENT_CHARS] + TRUNCATION_MARKER
    return (
        f'<untrusted_data source="{source}" id="{tag_id}">\n'
        f"{body}\n"
        f"</untrusted_data>"
    )

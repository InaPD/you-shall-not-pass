"""`metadata` family: the payload never appears on the page (spec 16.2).

Document metadata is attacker-controlled and invisible in every PDF viewer, but
an undefended pipeline that dumps "everything it can extract" into the prompt
reads it anyway. That is the whole point of the family.

  pdf_info -> the Info dictionary (Author / Subject / Keywords)
  pdf_xmp  -> the XMP packet (dc:description), with the Info dict left clean

Metadata is also the carrier that survives non-Latin-1 payloads: reportlab's
standard fonts mangle those in body text, PDF strings do not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pymupdf

from corpus.templates.pdf_resume import render

PLACEMENTS = ("pdf_info", "pdf_xmp")

_XMP = """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">{title}</rdf:li></rdf:Alt></dc:title>
   <dc:description><rdf:Alt>
    <rdf:li xml:lang="x-default">{payload}</rdf:li>
   </rdf:Alt></dc:description>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def build(
    profile: dict[str, Any],
    payload: str,
    out_dir: Path,
    attack_id: str,
    *,
    placement: str = "pdf_info",
) -> Path:
    out_path = Path(out_dir) / f"{attack_id}.pdf"
    name = profile.get("full_name", "Resume")

    if placement == "pdf_info":
        render(
            profile,
            out_path,
            metadata={
                "author": name,
                "subject": payload,
                "keywords": " ".join(payload.split()[:20]),
            },
        )
        return out_path

    if placement == "pdf_xmp":
        # Info dict stays clean so the attack is specifically an XMP attack.
        render(profile, out_path, metadata={"author": name, "subject": "Resume"})
        with pymupdf.open(out_path) as doc:
            doc.set_xml_metadata(
                _XMP.format(title=_escape(name), payload=_escape(payload))
            )
            doc.saveIncr()
        return out_path

    raise ValueError(f"unknown metadata placement {placement!r}")

"""Minimal solid-colour PNG encoder.

Used by the `behind_image` placement, which needs a real embedded image so that
ING-004 has something to find - a reportlab vector rectangle is not an image and
never appears in `page.get_images()`.

Hand-rolled rather than via Pillow: Pillow is only a transitive dependency of
reportlab and the dependency list in spec 4 is a hard constraint.
"""

from __future__ import annotations

import struct
import zlib


def _chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def solid_png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    """An opaque `width` x `height` PNG filled with `rgb`."""
    row = bytes((0, *(rgb * width)))  # filter byte 0, then RGB triples
    raw = row * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b"")
    )

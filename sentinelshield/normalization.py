"""Conservative input normalization before rule inspection."""

from __future__ import annotations

from html import unescape
from urllib.parse import unquote


def normalize_for_inspection(value: str) -> str:
    """Decode one layer of percent-encoding and HTML entities.

    Only one URL-decoding pass is performed intentionally. Repeated decoding can
    make rule behavior difficult to explain and should be designed deliberately in
    a production gateway.
    """

    return unescape(unquote(value))

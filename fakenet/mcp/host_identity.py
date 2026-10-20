"""Canonical VMware BIOS UUID identity across VMX bytes and SMBIOS text."""
from __future__ import annotations
import re
import uuid


def normal_uuid(value):
    text = str(value or '').strip()
    # VMX uuid.bios is a sequence of raw bytes. SMBIOS displays the first
    # three integer fields little endian. A normal UUID string is already in
    # display order and must never be byte swapped a second time.
    if re.fullmatch(r'[0-9a-fA-F]{2}(?:[ -][0-9a-fA-F]{2}){15}', text):
        return uuid.UUID(bytes_le=bytes.fromhex(text.replace('-', ' '))).hex
    try:
        return uuid.UUID(text).hex
    except (ValueError, TypeError, AttributeError):
        return ''

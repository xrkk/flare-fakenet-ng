"""Probe actual link semantics; Wine may return success without a link."""
import os
import tempfile
from pathlib import Path


def can_symlink():
    try:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            link = Path(directory) / 'link'
            target.write_bytes(b'original')
            os.symlink(target, link)
            return link.is_symlink() and link.read_bytes() == b'original'
    except OSError:
        return False

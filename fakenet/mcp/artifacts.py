# Copyright 2026 Google LLC
"""Managed artifact registration and metadata (P04 IMP-P04-04, OUT-015).

Products (PCAPs, run logs, reports, incident packs) register under
``%ProgramData%\\FakeNet-NG-MCP\\artifacts\\<run_id>\\``; the MCP surface
exposes ONLY normalized path/type/size/complete/sha256 — never content.
"""

import hashlib
from pathlib import Path


# Producers stage under these suffixes and publish with an atomic replace;
# anything still carrying one is not a finished artifact.
IN_PROGRESS_SUFFIXES = ('.part', '.partial')


def is_published(name):
    """True only for names this product publishes atomically."""
    return not str(name).lower().endswith(IN_PROGRESS_SUFFIXES)


class ArtifactRegistry:

    def __init__(self, artifacts_root):
        self.root = Path(artifacts_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def run_dir(self, run_id):
        return self.root / str(run_id)

    def register_fakenet_outputs(self, run_id, package_root, keep=None,
                                 prefix='fakenet-'):
        """Register the artifacts a finished FakeNet run leaves next to the
        package (PCAPs, fakenet log, report) plus the incident pack.
        ``keep(path) -> bool`` filters which files belong to the run (the
        supervisor passes an mtime window so earlier runs' outputs are
        not re-registered on every stop)."""
        import shutil

        run_dir = self.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        source = Path(package_root)
        copied = []
        for pattern in ('*.pcap', '*.log', '*report*.html', '*.json'):
            for path in sorted(source.glob(pattern)):
                if path.parent != source:
                    continue
                if keep is not None and not keep(path):
                    continue
                destination = run_dir / (prefix + path.name)
                if not destination.exists():
                    shutil.copy2(path, destination)
                copied.append(destination)
        return copied

    def metadata(self):
        """All registered artifacts as metadata-only entries."""
        items = []
        if not self.root.is_dir():
            return items
        for path in sorted(self.root.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            suffix = path.suffix.lstrip('.').lower()
            item_type = {'pcap': 'pcap', 'log': 'log', 'html': 'report',
                         'dmp': 'userdump', 'ini': 'config'}.get(
                             suffix, suffix or 'file')
            published = is_published(path.name)
            items.append({
                'path': str(path),
                'type': item_type,
                'size': path.stat().st_size,
                'complete': published,
                # An unpublished name still being written has no final
                # content, so it must not advertise a final digest.
                'sha256': (hashlib.sha256(path.read_bytes()).hexdigest()
                           if published else None),
            })
        return items

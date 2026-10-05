"""Read local source graphs without importing scripts or starting business."""
from __future__ import annotations

import ast
from .context import MaterialError, exact_path

def require(condition, reason):
    if not condition:
        raise MaterialError(reason)


def source_closure(source_root, entry, *, dynamic=(), root_modules=()):
    """Static local imports plus explicitly enumerated dynamic files/scripts."""
    local = source_root / 'test/mcp/acceptance'
    def module(name):
        base = source_root if (name == 'fakenet' or name.startswith('fakenet.')
                               or name.split('.')[0] in root_modules) else local
        path = base.joinpath(*name.split('.'))
        if path.with_suffix('.py').is_file(): return path.with_suffix('.py')
        if (path / '__init__.py').is_file(): return path / '__init__.py'
        if name.split('.')[0] in root_modules or name.startswith(('fakenet.', 'formal_runtime.', 'scenario_', 'sst_', 'etl_', 'tdh_')):
            raise MaterialError('local static source dependency missing: ' + name)
        return None
    pending = [entry, *(local / name for name in dynamic), *(source_root/(name+'.py') for name in root_modules)]
    seen = set()
    while pending:
        path = exact_path(str(pending.pop()))
        if path in seen: continue
        require(path.is_file(), 'entry dependency missing: ' + str(path))
        seen.add(path)
        root = source_root if path.is_relative_to(source_root / 'fakenet') or path.parent == source_root else local
        relative = path.relative_to(root)
        parts = list(relative.with_suffix('').parts)
        package = parts[:-1]
        for i in range(1,len(package)+1):
            parent = root.joinpath(*package[:i]) / '__init__.py'
            if parent.is_file(): pending.append(parent)
        if path.suffix != '.py':
            continue  # Staged PowerShell/embedded source is fingerprinted bytes.
        tree = ast.parse(path.read_bytes(), filename=str(path))
        names = []
        for node in ast.walk(tree):
            if isinstance(node,ast.Import): names.extend(row.name for row in node.names)
            elif isinstance(node,ast.ImportFrom):
                if node.level:
                    base = package[:len(package)-node.level+1]
                    name = '.'.join(base + ([node.module] if node.module else []))
                else: name = node.module or ''
                if name: names.append(name)
                # A from-import can name a module or a value. Only an actual
                # sibling file/package is a further local dependency.
                for row in node.names:
                    child = name + '.' + row.name if name else row.name
                    base = source_root if child.startswith('fakenet.') or child.split('.')[0] in root_modules else local
                    test = base.joinpath(*child.split('.'))
                    if test.with_suffix('.py').is_file() or (test/'__init__.py').is_file(): names.append(child)
        for name in names:
            path = module(name)
            if path is not None: pending.append(path)
    return seen

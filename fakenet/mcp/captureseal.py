"""Run-owned Linux capture checkpoint IPC; it never stops network routing."""
import hashlib
import json
import sys
import os
from pathlib import Path
import re
import stat
import time
import uuid

BASE_LOGS = Path(__file__).absolute().parents[2] / 'Logs'


def _plain(path, directory=False):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('linked capture control/original path')
    st = path.stat()
    good = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not good or st.st_uid != os.geteuid() or (not directory and st.st_nlink != 1):
        raise ValueError('capture control/original identity')
    return st


def _root(path):
    path = Path(path).absolute()
    if (path.parent != BASE_LOGS.absolute() or
            not re.fullmatch(r'capture-seal-[0-9a-f]{32}', path.name)):
        raise ValueError('foreign capture control root')
    for parent in (BASE_LOGS, BASE_LOGS.parent):
        parent_stat = _plain(parent, True)
        if stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise ValueError('writable capture control parent')
    st = _plain(path, True)
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError('capture control protection')
    return path


def create_control(run_id):
    if not re.fullmatch(r'[0-9a-f]{32}', run_id):
        raise ValueError('invalid Linux run identity')
    # Check existing parents before creating anything. This optional
    # feature never tightens a legacy launcher by changing directory modes.
    for parent in (BASE_LOGS.parent, BASE_LOGS):
        if parent.exists():
            st = _plain(parent, True)
            if stat.S_IMODE(st.st_mode) & 0o022:
                raise ValueError('writable capture control parent')
    BASE_LOGS.mkdir(mode=0o755, parents=True, exist_ok=True)
    _plain(BASE_LOGS, True)
    root = BASE_LOGS / ('capture-seal-' + run_id)
    root.mkdir(mode=0o700, exist_ok=False)
    _root(root)
    return root


def _write(path, value):
    path = Path(path)
    # The protected run root has one coordinator writer and one child
    # reply writer. Publish only closed JSON, never a visible half-write.
    if path.exists() or path.is_symlink():
        raise ValueError('capture control already published')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    temporary = path.parent / ('.' + path.name + '.' + uuid.uuid4().hex + '.part')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() or path.is_symlink():
            raise ValueError('capture control already published')
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read(path):
    st = _plain(path)
    if stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 65536:
        raise ValueError('capture control size/protection')
    raw = Path(path).read_bytes()
    now = _plain(path)
    if (st.st_dev, st.st_ino, st.st_size) != (now.st_dev, now.st_ino, len(raw)):
        raise ValueError('capture control changed while reading')
    return json.loads(raw)


def _birth(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]


def file_fact(path):
    path = Path(path).absolute()
    st = _plain(path)
    if st.st_size > 256 * 1024 * 1024:
        raise ValueError('capture original exceeds checkpoint limit')
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(chunk)
            digest.update(chunk)
    after = _plain(path)
    if (st.st_dev, st.st_ino, st.st_size) != (after.st_dev, after.st_ino, size):
        raise ValueError('capture original changed')
    return dict(path=str(path), bytes=size, sha256=digest.hexdigest(),
                device=st.st_dev, inode=st.st_ino)


def verify_files(files):
    if not isinstance(files, list) or not files:
        raise ValueError('capture checkpoint has no originals')
    for item in files:
        current = file_fact(item['path'])
        if any(current[key] != item[key] for key in current):
            raise ValueError('capture checkpoint original changed')


def request_checkpoint(root, proc, command_id, timeout=30):
    root = _root(root)
    command_id = str(uuid.UUID(command_id))
    if proc.poll() is not None:
        raise ValueError('capture process already ended')
    request = dict(schema='fakenet.capture-control.v1', command_id=command_id,
                   pid=proc.pid, birth=_birth(proc.pid), run_id=root.name[13:])
    target = root / ('request-' + command_id + '.json')
    response = root / ('response-' + command_id + '.json')
    if target.exists():
        if _read(target) != request:
            raise ValueError('capture command identity conflict')
    else:
        _write(target, request)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if response.exists():
            value = _read(response)
            if value.get('request') != request:
                raise ValueError('capture response identity mismatch')
            if proc.poll() is not None or _birth(proc.pid) != request['birth']:
                raise ValueError('capture process ended or changed')
            if value.get('error'):
                raise ValueError('capture checkpoint failed: ' + value['error'])
            checkpoint = value['checkpoint']
            verify_files(checkpoint['files'])
            return dict(checkpoint, process=dict(pid=proc.pid, birth=request['birth']),
                        control_request=str(target), control_response=str(response))
        if proc.poll() is not None:
            raise ValueError('capture process ended before checkpoint')
        time.sleep(0.05)
    raise TimeoutError('capture command submitted; outcome unknown; do not resend')


def _log_prefix(root, request):
    """Freeze a true stdout/stderr log prefix; the routing log may continue."""
    source = root.parent / ('runner-child-' + request['run_id'] + '.log')
    st = _plain(source)
    output = os.fstat(1)
    if (output.st_dev, output.st_ino) != (st.st_dev, st.st_ino):
        raise ValueError('runner log is not this process stdout')
    if st.st_size > 32 * 1024 * 1024:
        raise ValueError('runner log prefix limit')
    target = root / ('runner-prefix-' + request['command_id'] + '.log')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out, source.open('rb') as original:
        left = st.st_size
        while left:
            chunk = original.read(min(left, 1024 * 1024))
            if not chunk:
                raise ValueError('runner log shrank while freezing prefix')
            out.write(chunk)
            left -= len(chunk)
        out.flush()
        os.fsync(out.fileno())
    after = _plain(source)
    if (after.st_dev, after.st_ino) != (st.st_dev, st.st_ino):
        raise ValueError('runner log was replaced')
    return dict(file_fact(target), role='log'), dict(
        path=str(source), device=st.st_dev, inode=st.st_ino,
        prefix_bytes=st.st_size, whole_run_complete=False)


def service_capture_request(fakenet, root):
    root = _root(root)
    for path in sorted(root.glob('request-*.json')):
        name = path.name[8:-5]
        if str(uuid.UUID(name)) != name:
            raise ValueError('invalid capture command file')
        response = root / ('response-' + name + '.json')
        if response.exists():
            continue
        request = _read(path)
        if (set(request) != {'schema', 'command_id', 'pid', 'birth', 'run_id'} or
                request['schema'] != 'fakenet.capture-control.v1' or
                request['command_id'] != name or request['run_id'] != root.name[13:] or
                request['pid'] != os.getpid() or request['birth'] != _birth(os.getpid())):
            raise ValueError('capture command not bound to this process')
        value = {'request': request}
        try:
            if fakenet.diverter is None:
                raise ValueError('no active diverter')
            checkpoint = fakenet.diverter.seal_capture_outputs()
            if 'log_source' not in checkpoint:
                sys.stdout.flush()
                sys.stderr.flush()
                log, log_source = _log_prefix(root, request)
                checkpoint['files'].append(log)
                checkpoint['log_source'] = log_source
            value['checkpoint'] = checkpoint
        except Exception as error:
            value['error'] = type(error).__name__ + ': ' + str(error)
        _write(response, value)

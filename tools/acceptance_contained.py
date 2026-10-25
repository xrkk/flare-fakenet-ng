"""Finite Docker/Wine preparation for three registered offline cases.

This controller only prepares their existing central plan/execute/judge inputs.
It never supplies acceptance verdicts or arbitrary container commands.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

IMAGE = 'sha256:1b33b518a7c71ecd13264f0d1c41faf254e301b8702e2da8ca11376cff700a5e'
WHEEL = 'wheelhouse/pydivert-2.1.0-py2.py3-none-any.whl'
WHEEL_SHA = '382db488e3c37c03ec9ec94e061a0b24334d78dbaeebb7d4e4d32ce4355d9da1'
CASES = {'linux': ['MCP-UNIT-PRODUCT', 'MCP-UNIT-TOOLING'],
         'wine': ['CORE-WINDOWS-OFFLINE']}
LABEL = 'fakenet.contained-offline'


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def checked_path(path):
    path = Path(os.path.abspath(path))
    if path.resolve() != path or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('linked output or source path is not permitted')
    return path


def output_path(root, output):
    path = checked_path(output)
    logs = root / 'Logs'
    if not path.is_relative_to(logs) or path == logs or path.exists():
        raise ValueError('output must be a fresh child of repository Logs')
    return path


def source_snapshot(root, git):
    import acceptance_source_identity as identity
    commit = git('rev-parse', 'HEAD').decode().strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('source must be an immutable Git commit')
    entries = git('ls-tree', '-r', '-z', commit)
    hashes = {}
    for item in entries.split(b'\0'):
        if not item:
            continue
        meta, name = item.split(b'\t', 1)
        mode, kind, oid = meta.decode('ascii').split()
        relative = name.decode('utf-8')
        p = Path(relative)
        if (p.is_absolute() or '..' in p.parts or relative in hashes
                or mode not in ('100644', '100755') or kind != 'blob'):
            raise ValueError('source tree contains a nonregular or ambiguous member')
        current = root / relative
        if checked_path(current) != current or not current.is_file():
            raise ValueError('source file is missing: ' + relative)
        blob, content = identity._file_identity(current, 'sha1')
        if blob != oid:
            raise ValueError('checkout differs from committed source: ' + relative)
        hashes[relative] = content
    if not hashes:
        raise ValueError('empty source snapshot')
    return commit, hashes


class Controller:
    def __init__(self, root, output, profile='all', seconds=900):
        self.root = checked_path(root)
        self.output = output_path(self.root, output)
        if profile not in ('all', 'linux', 'wine'):
            raise ValueError('unknown finite offline profile')
        if os.name != 'posix' or os.getuid() != 1000:
            raise ValueError('this pinned environment requires Linux uid 1000')
        self.profiles = ['linux', 'wine'] if profile == 'all' else [profile]
        self.deadline = time.monotonic() + seconds
        self.owner = str(uuid.uuid4())
        self.cid = None
        self.creation_attempted = False
        self.sequence = 0
        self.output.mkdir(parents=True, exist_ok=False)
        self.controls = self.output / 'control'
        self.evidence = self.output / 'evidence'
        self.controls.mkdir()
        self.evidence.mkdir()
        self.record = {'schema': 'fakenet.contained-run.v1', 'owner': self.owner,
                       'status': 'preparing', 'full_functional_pass': False,
                       'native_credit': False, 'profiles': self.profiles, 'commands': []}

    def call(self, name, argv, *, limit=60, cleanup=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 and not cleanup:
            raise TimeoutError('contained run deadline exceeded')
        self.sequence += 1
        stem = self.output / ('%02d-%s' % (self.sequence, name))
        started = time.monotonic()
        entry = {'argv': list(map(str, argv)), 'name': name,
                 'stdout': str(stem.with_suffix('.stdout')),
                 'stderr': str(stem.with_suffix('.stderr'))}
        self.record['commands'].append(entry)
        try:
            p = subprocess.run(argv, capture_output=True, timeout=(limit if cleanup else min(limit, remaining)),
                               env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
            out, err = p.stdout, p.stderr
            entry['returncode'] = p.returncode
        except subprocess.TimeoutExpired as exc:
            out, err = exc.stdout or b'', exc.stderr or b''
            entry.update(returncode=124, timed_out=True)
        entry['elapsed'] = time.monotonic() - started
        stem.with_suffix('.stdout').write_bytes(out)
        stem.with_suffix('.stderr').write_bytes(err)
        if entry['returncode']:
            raise RuntimeError('%s failed (rc=%s); see %s' % (name, entry['returncode'], stem))
        return out

    def git(self, *args):
        return self.call('git', ['git', '-C', str(self.root), *args])

    def inspect(self, cleanup=False):
        if not self.cid or not re.fullmatch(r'[0-9a-f]{64}', self.cid):
            raise ValueError('no known full container ID')
        value = json.loads(self.call('inspect', ['docker', 'inspect', self.cid], cleanup=cleanup))[0]
        if (value['Id'] != self.cid or value['Image'] != IMAGE
                or value['Config'].get('Labels', {}).get(LABEL) != self.owner):
            raise ValueError('container ownership or image differs; cleanup refused')
        return value

    def verify_boundary(self, value):
        host, config = value['HostConfig'], value['Config']
        if (host['NetworkMode'] != 'none' or not host['ReadonlyRootfs']
                or config['User'] != '1000:1000' or 'ALL' not in host['CapDrop']
                or not any(x.startswith('no-new-privileges') for x in host['SecurityOpt'])
                or host['PidsLimit'] != 256 or host['Memory'] != 2 * 1024**3
                or host['NanoCpus'] != 2 * 10**9):
            raise ValueError('actual container security options differ')
        mounts = {m['Destination']: m for m in value['Mounts'] if m['Type'] == 'bind'}
        expected = {'/workspace': self.root, str(self.root): self.root,
                    '/run-control': self.controls, '/out': self.evidence}
        if set(mounts) != set(expected):
            raise ValueError('unexpected container bind mounts')
        for dest, source in expected.items():
            if mounts[dest]['Source'] != str(source) or mounts[dest]['RW'] != (dest == '/out'):
                raise ValueError('actual source/control/output mount differs')

    def create(self):
        argv = ['docker', 'run', '--detach', '--pull=never', '--cidfile', str(self.output/'container.cid'),
                '--label', LABEL+'='+self.owner, '--network', 'none', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '1000:1000',
                '--pids-limit', '256', '--memory', '2g', '--cpus', '2',
                '--tmpfs', '/tmp:rw,size=1536m,mode=1777', '--tmpfs', '/run:rw,size=16m,mode=1777',
                '--env', 'HOME=/out/windows/home', '--env', 'WINEPREFIX=/out/windows/home/wine',
                '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
                '--env', 'GIT_OPTIONAL_LOCKS=0',
                '--env', 'PYTEST_ADDOPTS=-p no:cacheprovider -o log_file=/out/central-pytest.log',
                '--env', 'PATH=/run-control/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
        for source, dest in [(self.root, '/workspace'), (self.root, str(self.root)),
                             (self.controls, '/run-control'), (self.evidence, '/out')]:
            if ',' in str(source):
                raise ValueError('comma in Docker bind path')
            argv += ['--mount', 'type=bind,src=%s,dst=%s%s' %
                     (source, dest, '' if dest == '/out' else ',readonly')]
        argv += ['--workdir', '/workspace', IMAGE, 'python3', '-B', '-c',
                 'import time;time.sleep(900)']
        self.creation_attempted = True
        try:
            self.call('create', argv)
        finally:
            cidfile = self.output/'container.cid'
            if cidfile.is_file() and not cidfile.is_symlink():
                self.cid = cidfile.read_text().strip()
                self.record['container_id'] = self.cid
        observed = self.inspect()
        self.verify_boundary(observed)
        save(self.output/'inspection.json', observed)

    def exec(self, name, args, limit=600):
        return self.call(name, ['docker', 'exec', self.cid, *args], limit=limit)

    def cleanup(self):
        if not self.cid:
            if self.creation_attempted:
                raise ValueError('container creation outcome unknown; no safe cleanup identity')
            return {'status': 'no_known_container'}
        self.inspect(cleanup=True)
        self.call('stop', ['docker', 'stop', '--time', '10', self.cid], cleanup=True)
        stopped = self.inspect(cleanup=True)
        if stopped['State']['Running'] or stopped['State']['Pid']:
            raise ValueError('owned container did not stop')
        save(self.output/'stopped.json', stopped)
        self.call('remove', ['docker', 'rm', self.cid], cleanup=True)
        return {'status': 'stopped_and_removed', 'container_id': self.cid}

    def run(self):
        code = 3
        try:
            commit, hashes = source_snapshot(self.root, self.git)
            self.record.update(source_commit=commit, source_files=len(hashes))
            images = json.loads(self.call('image', ['docker', 'image', 'inspect', IMAGE]))
            if len(images) != 1 or images[0]['Id'] != IMAGE:
                raise ValueError('fixed local image is unavailable')
            save(self.output/'image.json', images[0])
            if 'wine' in self.profiles and digest(self.root/WHEEL) != WHEEL_SHA:
                raise ValueError('offline wheel identity differs')
            python = str(self.root/'.venv-mcp-runners/bin/python')
            if not Path(python).is_file():
                raise ValueError('stable project .venv-mcp-runners Python is missing')
            save(self.controls/'request.json', {'profiles': self.profiles, 'python': python})
            bridge = self.controls/'wine-python'
            bridge.write_text(WINE_BRIDGE, encoding='utf-8')
            bridge.chmod(0o755)
            bindir = self.controls/'bin'
            bindir.mkdir()
            git_bridge = bindir/'git'
            git_bridge.write_text(GIT_BRIDGE, encoding='utf-8')
            git_bridge.chmod(0o755)
            self.create()
            self.exec('prepare', [python, '-B', '/workspace/tools/acceptance_contained.py', '_prepare'], limit=180)
            facts = json.loads((self.evidence/'runtime.json').read_text())
            witness = {'schema': 'fakenet.contained-collection.v1', 'image': IMAGE,
                       'container_id': self.cid, 'source_commit': commit, 'source_root': '/workspace',
                       'work_root': '/out', 'source_hashes': hashes, 'interpreters': facts}
            save(self.controls/'attestation.json', witness)
            save(self.evidence/'candidate.json', {'schema': 'fakenet.acceptance-candidate.v2',
                                                 'source_commit': commit})
            summaries = []
            for profile in self.profiles:
                kind = profile+'-contained-v1'
                environment = {'schema': 'fakenet.acceptance-environment.v2',
                    'targets': ['host-linux' if profile == 'linux' else 'host-windows'],
                    'interpreters': {'python': facts[kind]['path']}, 'work_root': '/out',
                    'allowed_actions': ['collection', 'offline-pytest'],
                    'collection_profile': {'kind': kind, 'attestation': '/run-control/attestation.json',
                                           'sha256': digest(self.controls/'attestation.json')}}
                save(self.evidence/(profile+'-environment.json'), environment)
                directory = '/out/'+profile
                commands = [('plan', ['plan', '--mode', 'selected', '--candidate', '/out/candidate.json',
                             '--environment', '/out/'+profile+'-environment.json', '--output', directory+'/plan.json']
                             + [x for case in CASES[profile] for x in ('--case', case)]),
                            ('execute', ['execute', '--plan', directory+'/plan.json']),
                            ('judge', ['judge', '--plan', directory+'/plan.json', '--results', directory+'/results',
                                       '--output', directory+'/independent-summary.json'])]
                for action, args in commands:
                    self.exec(profile+'-'+action, [python, '-B', '/workspace/tools/acceptance.py', *args])
                summary = self.evidence/profile/'independent-summary.json'
                value = json.loads(summary.read_text())
                if value['verdict'] != 'pass' or value['full_functional_pass']:
                    raise ValueError('selected offline judge did not pass')
                summaries.append({'path': str(summary), 'sha256': digest(summary),
                                  'case_ids': CASES[profile]})
            self.record.update(status='selected_offline_pass', summaries=summaries)
            code = 0
        except (ValueError, OSError, RuntimeError, TimeoutError, KeyError) as exc:
            self.record.update(status='failed', error=str(exc))
        finally:
            try:
                self.record['cleanup'] = self.cleanup()
            except (ValueError, OSError, RuntimeError, KeyError) as exc:
                self.record.update(status='cleanup_failed', cleanup_error=str(exc))
                code = 3
            self.record['returncode'] = code
            save(self.output/'run.json', self.record)
        return code


GIT_BRIDGE = "#!/usr/bin/python3\nimport os,sys,json,time\nwith open('/out/git.jsonl','a') as stream:\n    stream.write(json.dumps({'time':time.time(),'argv':sys.argv[1:]})+'\\n')\nos.execv('/usr/bin/git',['git',*sys.argv[1:]])\n"


WINE_BRIDGE = r'''#!/usr/bin/python3
import os,sys,subprocess
if sys.argv[1:4] != ['-B','-m','pytest']:
    raise SystemExit('only registered pytest invocation is supported')
def win(value):
    return 'Z:'+value.replace('/','\\') if value.startswith('/') else value
env=os.environ.copy();env.pop('TMPDIR',None)
for name in ('TMP','TEMP'):
    if name in env:env[name]=win(env[name])
env['PYTHONPATH']=win('/workspace')
env['PYTEST_ADDOPTS']='-p no:cacheprovider -o log_file=Z:/out/wine-pytest.log'
p=subprocess.run(['xvfb-run','-a','wine',r'C:\Python311\python.exe',*[win(x) for x in sys.argv[1:]]],env=env,cwd='/workspace',capture_output=True)
sys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr);sys.exit(p.returncode)
'''


def prepare():
    """Fixed internal operation, called only inside the inspected container."""
    request = json.loads(Path('/run-control/request.json').read_text())
    import acceptance
    acceptance._contained_kernel('/workspace', '/out')
    import pytest
    import mcp
    python = Path(request['python'])
    if python.resolve() != Path(sys.executable).resolve():
        raise ValueError('active preparation interpreter differs')
    facts = {'linux-contained-v1': {'path': str(python), 'sha256': digest(python),
             'dependencies': {str(Path(p)): digest(p) for p in (pytest.__file__, mcp.__file__)}}}
    if 'wine' in request['profiles']:
        base, dest = Path('/opt/fakenet-wine'), Path('/out/windows/home/wine')
        dest.parent.mkdir(parents=True, exist_ok=False)
        total, members = 0, 0
        for parent, dirs, names in os.walk(base, followlinks=False):
            for name in dirs+names:
                path = Path(parent)/name
                info = path.lstat()
                members += 1
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
                elif not (stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                    raise ValueError('unexpected prefix member')
                if members > 80000 or total > 4*1024**3:
                    raise ValueError('installed prefix exceeds limits')
        if not base.is_dir() or base.is_symlink() or shutil.disk_usage(dest.parent).free < total+512*1024**2:
            raise ValueError('invalid prefix source or insufficient disk space')
        shutil.copytree(base, dest, symlinks=True)
        wheel = Path('/workspace')/WHEEL
        if digest(wheel) != WHEEL_SHA:
            raise ValueError('offline wheel changed')
        args = ['xvfb-run', '-a', 'wine', r'C:\Python311\python.exe', '-B', '-m', 'pip', 'install',
                '--no-index', '--no-deps', '--no-cache-dir', '--force-reinstall',
                'Z:/workspace/'+WHEEL]
        result = subprocess.run(args, capture_output=True, timeout=90)
        Path('/out/wheel-install.stdout').write_bytes(result.stdout)
        Path('/out/wheel-install.stderr').write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError('owned offline wheel installation failed')
        installed = dest/'drive_c/Python311/Lib/site-packages/pydivert'
        facts['wine-contained-v1'] = {'path': '/run-control/wine-python',
            'sha256': digest('/run-control/wine-python'),
            'dependencies': {str(p): digest(p) for p in installed.rglob('*') if p.is_file()},
            'pydivert_version': '2.1.0', 'pydivert_root': str(installed)}
        save('/out/prefix-preparation.json', {'members': members, 'bytes': total, 'source': str(base),
                                            'owned_prefix': str(dest)})
    save('/out/runtime.json', facts)


def launch(root, output=None, profile='all'):
    root = checked_path(root)
    output = output or root/'Logs/acceptance'/('contained-'+str(uuid.uuid4()))
    controller = Controller(root, output, profile)
    code = controller.run()
    print(json.dumps({'status': controller.record['status'], 'run': str(controller.output),
                      'full_functional_pass': False, 'native_credit': False}))
    return code


if __name__ == '__main__':
    if sys.argv[1:] != ['_prepare']:
        raise SystemExit('use tools/acceptance.py contained-offline')
    prepare()

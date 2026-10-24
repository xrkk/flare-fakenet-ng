"""Observe and recover one exact route added by the original acceptance owner.

This restores driver-owned state; it does not claim that the original product
stop callback removes default routes. No broad route replacement is supported.
"""
import ipaddress
import json
import re
import subprocess


def canonical(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('route snapshot must contain original object rows')
    if any(row.get('dst') != 'default' for row in rows):
        raise ValueError('default route snapshot contains another destination')
    return sorted([json.loads(json.dumps(row, sort_keys=True)) for row in rows],
                  key=lambda row: json.dumps(row, sort_keys=True))


def route_snapshot():
    result = subprocess.run(['ip', '-4', '-j', 'route', 'show', 'table', 'all'],
                            capture_output=True, text=True, check=True, timeout=10)
    return canonical([row for row in json.loads(result.stdout) if row.get('dst') == 'default'])


def delete_command(row):
    allowed = {'dst', 'gateway', 'dev', 'table', 'protocol', 'scope', 'prefsrc', 'metric', 'flags'}
    if set(row) - allowed or row.get('dst') != 'default' or row.get('flags', []) != []:
        raise ValueError('route attributes cannot be recovered exactly')
    ipaddress.IPv4Address(row['gateway'])
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', row['dev']):
        raise ValueError('invalid route device')
    argv = ['ip', '-4', 'route', 'del', 'default', 'via', row['gateway'], 'dev', row['dev']]
    for name, option in [('table', 'table'), ('protocol', 'proto'), ('scope', 'scope'),
                         ('prefsrc', 'src'), ('metric', 'metric')]:
        if name in row:
            text = str(row[name])
            if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', text):
                raise ValueError('invalid route qualifier')
            if name == 'prefsrc': ipaddress.IPv4Address(text)
            argv.extend([option, text])
    return argv


def route_delete(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=10).returncode


def owned_row(before, active, ipv4, interface, original_add_succeeded):
    before, active = canonical(before), canonical(active)
    if not original_add_succeeded:
        if before != active: raise ValueError('unowned route drift without original successful add')
        return None
    # Never remove a preexisting default to manufacture a positive precondition.
    if before: raise ValueError('original add was not from the no-default precondition')
    if len(active) != 1: raise ValueError('added route is ambiguous or foreign')
    row = active[0]
    if row.get('gateway') != ipv4 or row.get('dev') != interface:
        raise ValueError('added route does not match the original target/interface')
    delete_command(row)
    return row


def recover_route(before, active, after_stop, ipv4, interface, add_succeeded, quiescent):
    result = dict(before=canonical(before), active=canonical(active),
                  after_stop=canonical(after_stop), after_recovery=None,
                  original_add_succeeded=add_succeeded, quiescent=quiescent,
                  original_stop_restored=canonical(before) == canonical(after_stop),
                  owned=None, command=None, returncode=None, restored=False, error=None)
    try:
        row = owned_row(before, active, ipv4, interface, add_succeeded)
        result['owned'] = row
        if not quiescent: raise ValueError('original route writer has not quiesced')
        # Re-observe immediately before mutation. Unknown concurrent rows refuse.
        observed = route_snapshot()
        if observed != result['after_stop']: raise ValueError('route changed after original stop')
        if row is not None and observed != canonical(before):
            if observed != canonical(active): raise ValueError('foreign default-route drift')
            argv = delete_command(row); result['command'] = argv
            result['returncode'] = route_delete(argv)
            if result['returncode'] != 0: raise ValueError('owned route removal failed')
        result['after_recovery'] = route_snapshot()
        if result['after_recovery'] != canonical(before): raise ValueError('route restoration not observed')
        result['restored'] = True
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        try: result['after_recovery'] = route_snapshot()
        except Exception: pass
    return result


def verify_route(result, ipv4, interface):
    row = owned_row(result['before'], result['active'], ipv4, interface,
                    result['original_add_succeeded'])
    if result.get('owned') != row or result.get('quiescent') is not True:
        raise ValueError('owned route identity/quiescence missing')
    before, active, stopped = map(canonical, (result['before'], result['active'], result['after_stop']))
    if result.get('original_stop_restored') != (before == stopped):
        raise ValueError('original stop limitation was changed')
    if stopped not in (before, active): raise ValueError('foreign route drift after stop')
    expected = delete_command(row) if row is not None and stopped != before else None
    if result.get('command') != expected or result.get('returncode') != (0 if expected else None):
        raise ValueError('exact owned recovery action missing')
    if canonical(result['after_recovery']) != before or result.get('restored') is not True or result.get('error'):
        raise ValueError('independent route restoration failed')
    return True


# Linux deployment v3 uses a new immutable update request after installation.
# These helpers do not turn fixture observations into native authority.
def _digest(path):
    import hashlib
    return hashlib.sha256(__import__('pathlib').Path(path).read_bytes()).hexdigest()


def _plain(path, base=None):
    from pathlib import Path
    import stat
    path=Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('linked or relative deployment object')
    if base is not None and not path.resolve().is_relative_to(Path(base).resolve()):
        raise ValueError('deployment object escaped its owner')
    if path.exists() and (not stat.S_ISREG(path.stat().st_mode) or path.stat().st_nlink!=1):
        raise ValueError('deployment file is not an unlinked regular object')
    return path


def template_data(package, pinned, updater_path):
    from pathlib import Path
    package=Path(package);path=_plain(package/'template.json')
    if _digest(path)!=pinned:raise ValueError('update template fingerprint changed')
    data=json.loads(path.read_text())
    names={'fakenet/mcp/linuxrunner.py','fakenet/diverters/linuxnetpolicy.py'}
    if (set(data)!={'schema','base_manifest','source_commit','files','updater_sha256','interpreter_sha256'}
            or data['schema']!='fakenet.linux-update-template.v1' or set(data['files'])!=names
            or data['base_manifest']!='9f09c2b2c0051af25e689914f1a5d3839e1112e0a70b0effb15fd38252e772ef'
            or not re.fullmatch('[0-9a-f]{40}',data['source_commit'])
            or not re.fullmatch('[0-9a-f]{64}',data['interpreter_sha256'])):
        raise ValueError('exact immutable update template required')
    expected=names|{'template.json','update-idle.py'}
    actual={p.relative_to(package).as_posix() for p in package.rglob('*') if not p.is_dir()}
    if actual!=expected:raise ValueError('update template file set differs')
    if _digest(_plain(package/'update-idle.py',package))!=data['updater_sha256'] or _digest(updater_path)!=data['updater_sha256']:
        raise ValueError('original updater bytes changed')
    for name,sha in data['files'].items():
        if _digest(_plain(package/name,package))!=sha:raise ValueError('template source changed: '+name)
    return data


def phase_package(template, template_pin, system_root, destination, install_receipt,
                  operation, binding, updater_path, fault=False):
    from pathlib import Path
    import os
    data=template_data(template,template_pin,updater_path)
    destination=Path(destination);root=Path(system_root);receipt=_plain(install_receipt,root/'opt')
    installed=json.loads(receipt.read_text())
    if installed.get('phase')!='completed' or installed.get('operation')!=operation:
        raise ValueError('phase package requires the original completed install receipt')
    if destination.exists() or destination.is_symlink():raise ValueError('phase package output collision')
    if any(p.is_symlink() for p in destination.parents):raise ValueError('linked phase output parent')
    token=_plain(root/'etc/fakenet-ng-linux/token',root)
    state=token.stat()
    if state.st_mode&0o777!=0o600:raise ValueError('original installed token permissions differ')
    target=root/'opt/fakenet-ng'
    old={name:_digest(_plain(target/name,target)) for name in data['files']}
    # The immutable parent template is never rewritten with the new inode.
    destination.mkdir(mode=0o700)
    for name in data['files']:
        path=destination/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        for parent in path.parents:
            if parent==destination:break
            parent.chmod(0o700)
        payload=(Path(template)/name).read_bytes()
        if fault and name=='fakenet/mcp/linuxrunner.py':
            payload=b"raise RuntimeError('FN-OWNED-UPDATE-IMPORT-FAILURE')\n"
        with path.open('xb') as stream:stream.write(payload)
        path.chmod(0o600)
    updater=destination/'update-idle.py';updater.write_bytes(Path(updater_path).read_bytes());updater.chmod(0o600)
    manifest=dict(base_manifest=data['base_manifest'],source_commit=data['source_commit'],
                  files={name:dict(old_sha256=old[name],new_sha256=_digest(destination/name)) for name in old},
                  base_files={'opt/fakenet-ng/'+name:sha for name,sha in old.items()},
                  token_inode=state.st_ino,updater_sha256=data['updater_sha256'],
                  interpreter_sha256=data['interpreter_sha256'])
    with (destination/'manifest.json').open('x') as stream:json.dump(manifest,stream,sort_keys=True,indent=2);stream.write('\n')
    (destination/'manifest.json').chmod(0o600)
    lineage=dict(schema='fakenet.linux-phase-update.v1',template_sha256=template_pin,
                 install_receipt_sha256=_digest(receipt),operation=operation,binding=binding,
                 token=dict(inode=state.st_ino,mode=0o600,sha256=_digest(token)),
                 manifest_sha256=_digest(destination/'manifest.json'),fault=fault,
                 files={p.relative_to(destination).as_posix():_digest(p) for p in destination.rglob('*') if p.is_file()})
    return lineage


def verify_phase_package(package, lineage, template, template_pin, install_bytes, token, binding):
    from pathlib import Path
    import hashlib
    package=Path(package);data=json.loads((Path(template)/'template.json').read_text())
    if (lineage.get('schema')!='fakenet.linux-phase-update.v1' or lineage.get('template_sha256')!=template_pin
            or _digest(Path(template)/'template.json')!=template_pin
            or lineage.get('install_receipt_sha256')!=hashlib.sha256(install_bytes).hexdigest()
            or json.loads(install_bytes).get('phase')!='completed'
            or lineage.get('operation')!=json.loads(install_bytes).get('operation')
            or lineage.get('token')!=token or lineage.get('binding')!=binding):
        raise ValueError('phase update provenance mismatch')
    actual={p.relative_to(package).as_posix():_digest(_plain(p,package)) for p in package.rglob('*') if p.is_file()}
    expected=set(data['files'])|{'manifest.json','update-idle.py'}
    if set(actual)!=expected or actual!=lineage.get('files') or actual['manifest.json']!=lineage.get('manifest_sha256'):
        raise ValueError('phase package file set/hash mismatch')
    manifest=json.loads((package/'manifest.json').read_text())
    if (manifest.get('base_manifest')!=data['base_manifest'] or manifest.get('source_commit')!=data['source_commit']
            or manifest.get('token_inode')!=token['inode'] or token['mode']!=0o600
            or manifest.get('updater_sha256')!=data['updater_sha256'] or actual['update-idle.py']!=data['updater_sha256']
            or manifest.get('interpreter_sha256')!=data['interpreter_sha256'] or set(manifest.get('files',{}))!=set(data['files'])
            or set(manifest.get('base_files',{}))!={'opt/fakenet-ng/'+name for name in data['files']}):
        raise ValueError('original update manifest constraints differ')
    for name,pin in data['files'].items():
        incoming=(Path(template)/name).read_bytes()
        if lineage.get('fault') and name=='fakenet/mcp/linuxrunner.py':incoming=b"raise RuntimeError('FN-OWNED-UPDATE-IMPORT-FAILURE')\n"
        row=manifest['files'][name]
        if (actual[name]!=hashlib.sha256(incoming).hexdigest() or row['new_sha256']!=actual[name]
                or row['old_sha256']!=manifest['base_files']['opt/fakenet-ng/'+name]):
            raise ValueError('phase package source/base mismatch')
    return manifest


def recover_published_update(receipt_path, system_root, package, quiet):
    from pathlib import Path
    import os
    receipt_path=_plain(receipt_path,Path(system_root)/'opt');before=_digest(receipt_path)
    receipt=json.loads(receipt_path.read_text());package=Path(package)
    manifest=json.loads(_plain(package/'manifest.json',package).read_text())
    names={'fakenet/mcp/linuxrunner.py','fakenet/diverters/linuxnetpolicy.py'}
    if (not re.fullmatch('[A-Za-z0-9-]{8,80}',receipt.get('operation',''))
            or receipt_path.parent.name!='.fakenet-update-'+receipt['operation']
            or receipt.get('failure_at')!='published'
            or receipt.get('phase')!='failed' or receipt.get('manifest')!=_digest(package/'manifest.json')
            or set(manifest.get('files',{}))!=names or set(receipt.get('published',[]))!=names
            or len(receipt.get('published',[]))!=len(set(receipt.get('published',[])))
            or set(receipt.get('originals',{}))!=names):
        raise ValueError('original failed-update identity/published set differs')
    if not quiet():raise ValueError('owned update writer is not quiescent')
    root=Path(system_root)/'opt/fakenet-ng';pending=[]
    for name in sorted(names):
        row=receipt['originals'][name];entry=manifest['files'][name]
        backup=_plain(row['backup'],receipt_path.parent/'originals');target=_plain(root/name,root)
        if (target.stat().st_uid!=row['uid'] or target.stat().st_gid!=row['gid'] or target.stat().st_mode&0o7777!=row['mode']
                or _digest(backup)!=row['sha256'] or row['sha256']!=entry['old_sha256']
                or _digest(target) not in (entry['old_sha256'],entry['new_sha256'])):
            raise ValueError('backup changed or target has foreign source drift')
        if _digest(target)==entry['new_sha256'] and name not in receipt['published']:
            raise ValueError('new source not published by this failed operation')
        pending.append((name,row,backup,target,_digest(target)))
    restored={}
    for name,row,backup,target,current in pending:
        if not quiet() or _digest(target)!=current:raise ValueError('writer/source changed before owned restore')
        temporary=target.with_name('.'+target.name+'.owned-restore-'+receipt['operation'])
        with temporary.open('xb') as stream:
            stream.write(backup.read_bytes());stream.flush();os.fsync(stream.fileno())
        temporary.chmod(row['mode']);os.replace(temporary,target)
        descriptor=os.open(str(target.parent),os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        if _digest(target)!=row['sha256']:raise ValueError('restored source bytes differ')
        restored[name]=dict(sha256=_digest(target),mode=target.stat().st_mode&0o7777,backup=str(backup))
    if _digest(receipt_path)!=before:raise ValueError('original failed receipt changed')
    return dict(receipt_sha256=before,operation=receipt['operation'],restored=restored,
                failed_receipt_preserved=True)


class NativeDeployment:
    """Fixed commands for an explicitly authorized, clean Linux installation.

    Expected identities come from the frozen preparation binding. Commands and
    paths are fixed here; callers cannot inject a shell or replace OS responses.
    """
    fixture=False
    owner=0
    unit='fakenet-ng-linux.service'

    def __init__(self, inputs):
        from pathlib import Path
        import os
        self.inputs=inputs;self.root=Path(inputs['system_root']);self.binding=inputs['binding']
        self.installed_receipt=None;self.last_pid=None;self.initial=None;self.created_objects=None
        required={'native','linux-install','linux-service','linux-fault-recovery'}
        if os.geteuid()!=0 or self.root!=Path('/') or not required.issubset(inputs['actions']):
            raise ValueError('explicit authorized root installation actions required')

    def command(self, argv):
        allowed=(argv[:2] in (['systemctl','stop'],['systemctl','start'],['systemctl','is-active'],['systemctl','show'],['systemctl','disable']))
        if argv==['systemctl','daemon-reload']:allowed=True
        if not allowed or (argv!=['systemctl','daemon-reload'] and argv[2]!=self.unit):
            raise ValueError('unregistered deployment lifecycle command')
        result=subprocess.run(argv,capture_output=True,text=True,timeout=30)
        if result.returncode:raise RuntimeError('owned deployment command failed: '+repr(argv))
        return result.stdout

    def _capture(self, argv):
        result=subprocess.run(argv,capture_output=True,text=True,timeout=20)
        if result.returncode:raise RuntimeError('native preflight observation failed: '+argv[0])
        return result.stdout

    def service(self):
        raw=self._capture(['systemctl','show',self.unit,'--property=LoadState,MainPID,ActiveState','--no-pager'])
        values=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        return dict(load=values['LoadState'],pid=int(values['MainPID']),active=values['ActiveState'])

    def _process(self,pid):
        from pathlib import Path
        import os
        base=Path('/proc')/str(pid)
        return dict(pid=pid,birth=base.joinpath('stat').read_text().rsplit(')',1)[1].split()[19],
                    executable=os.readlink(base/'exe'),interpreter_sha256=_digest(base/'exe'),
                    argv=(base/'cmdline').read_bytes().decode().split('\0')[:-1],
                    children=(base/'task'/str(pid)/'children').read_text().strip())

    def machine(self):
        from pathlib import Path
        import hashlib
        b=self.binding
        if Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()!=b['vm_uuid'] or Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=b['boot_id']:
            raise ValueError('current Linux target/boot identity differs')
        observations={}
        if set(b['control_services'])!={'remnux-control.service','maltrace-p03-debug.service'}:
            raise ValueError('both original control-service bindings required')
        for unit,expected in b['control_services'].items():
            pid=int(self._capture(['systemctl','show',unit,'--property=MainPID','--value']))
            process=self._process(pid)
            if pid!=expected['pid'] or process['birth']!=str(expected['birth']):raise ValueError('control service process identity differs')
            observations[unit]=dict(pid=pid,birth=process['birth'])
        envelope=json.loads(Path('/var/lib/maltrace/remnux-control/state.json').read_bytes())
        body=json.dumps(envelope['payload'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        if hashlib.sha256(body).hexdigest()!=envelope['sha256']:raise ValueError('original control-state checksum differs')
        state={key:envelope['payload'][key] for key in ('request_epoch','credential_generation','namespace','gate')}
        if state!=b['control_state'] or state['gate']!='OPEN' or state['request_epoch']!=state['credential_generation']:
            raise ValueError('current control epoch/namespace/gate differs')
        if self._capture(['ss','-Hnt','state','established','( sport = :28788 )']).strip():raise ValueError('unknown active update client')
        rules={}
        for executable in ('iptables-save','ip6tables-save','iptables-legacy-save','ip6tables-legacy-save'):
            raw=self._capture([executable]);rules[executable]=raw
            if any(line.startswith('-A ') or line.startswith(':') and ' DROP ' in line for line in raw.splitlines()):raise ValueError('original idle firewall precondition differs')
        nft=json.loads(self._capture(['nft','-j','list','ruleset']))
        if any('rule' in item for item in nft['nftables']):raise ValueError('active nft policy')
        return dict(vm_uuid=b['vm_uuid'],boot_id=b['boot_id'],control_services=observations,control_state=state,rules=rules,nft=nft)

    def clean(self):
        from pathlib import Path
        self.initial=self.machine();service=self.service()
        paths=['opt/fakenet-ng','etc/fakenet-ng-linux','etc/systemd/system/'+self.unit]
        if service['load']!='not-found' or service['pid']!=0 or any((self.root/name).exists() or (self.root/name).is_symlink() for name in paths):
            raise ValueError('fresh native target is not clean; no existing installation is removed')
        return dict(machine=self.initial,service=service,paths_absent=paths)

    def install_run(self,argv):
        from acceptance_linux_runtime import _deploy_module
        return _deploy_module().command(argv)

    def installed(self,receipt):
        self.installed_receipt=receipt
        if self.created_objects is None:self.created_objects=installation_inventory(self.root)
        service=self.service();process=self._process(service['pid'])
        if service['pid']<=0 or process['children'] or process['interpreter_sha256']!=self.binding['interpreter_sha256'] or process['argv']!=self.binding['service_argv']:
            raise ValueError('new owned installation process differs')
        self.last_pid=process
        return dict(service=service,process=process)

    def preflight(self,manifest):
        from pathlib import Path
        self.machine();service=self.service();process=self._process(service['pid'])
        if self.last_pid is None or process['pid']!=self.last_pid['pid'] or process['birth']!=self.last_pid['birth'] or process['children']:
            raise ValueError('owned installation birth/children changed')
        if process['interpreter_sha256']!=manifest['interpreter_sha256'] or process['argv']!=self.binding['service_argv']:
            raise ValueError('original interpreter/argv checks differ')
        return process

    def status(self):
        # Original updater reads only its own installed private token and never
        # exports it. This is the same original protocol/status implementation.
        from acceptance_linux_runtime import _update_module
        return _update_module().status()

    def quiet(self):
        service=self.service()
        return service['pid']==0 and service['active'] not in ('active','activating','deactivating')

    def stop(self):
        self.command(['systemctl','stop',self.unit])
        if not self.quiet():raise ValueError('owned installation did not stop')
        return self.service()

    def started(self):
        return self.installed(self.installed_receipt)

    def cleanup(self, expected):
        self.stop();self.command(['systemctl','disable',self.unit])
        remove_created_installation(self.root,self.created_objects,expected)
        self.command(['systemctl','daemon-reload'])
        after=self.service();machine=self.machine()
        if after['load']!='not-found' or after['pid']!=0 or stable_machine(machine)!=stable_machine(self.initial):
            raise ValueError('initial system state not restored')
        return dict(service=after,machine=machine,paths_absent=['opt/fakenet-ng','etc/fakenet-ng-linux','etc/systemd/system/'+self.unit],restored=True)


def stable_machine(value):
    result=dict(value)
    result['rules']={name:[re.sub(r'\[\d+:\d+\]','[0:0]',line.strip()) for line in text.splitlines() if line.strip() and not line.startswith('#')] for name,text in value.get('rules',{}).items()}
    if 'nft' in result:result['nft']={'nftables':[row for row in result['nft']['nftables'] if 'metainfo' not in row]}
    return result


def installation_inventory(root):
    from pathlib import Path
    import os,stat
    root=Path(root);rows={}
    for relative in ('opt/fakenet-ng','etc/fakenet-ng-linux','etc/systemd/system/fakenet-ng-linux.service'):
        base=root/relative
        if not base.exists() and not base.is_symlink():continue
        for path in [base]+(sorted(base.rglob('*')) if base.is_dir() and not base.is_symlink() else []):
            s=path.lstat();item=dict(inode=s.st_ino,device=s.st_dev,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
            if path.is_symlink():item.update(kind='symlink',target=os.readlink(path))
            elif path.is_dir():item['kind']='directory'
            elif path.is_file():
                if s.st_nlink!=1:raise ValueError('linked installation file')
                item.update(kind='file',sha256=_digest(path))
            else:raise ValueError('unexpected installation object')
            rows[path.relative_to(root).as_posix()]=item
    return rows


def remove_created_installation(root, created, expected_updates):
    from pathlib import Path
    root=Path(root);actual=installation_inventory(root)
    allowed={'opt/fakenet-ng/fakenet/mcp/linuxrunner.py','opt/fakenet-ng/fakenet/diverters/linuxnetpolicy.py'}
    if not isinstance(created,dict) or set(expected_updates)!=allowed or set(actual)!=set(created):
        raise ValueError('owned installation object set changed; preserve it')
    for name,before in created.items():
        current=actual[name]
        if name in allowed:
            if (current.get('sha256')!=expected_updates[name] or any(current[k]!=before[k] for k in ('mode','uid','gid','kind','device'))):
                raise ValueError('unexpected updated source metadata')
        elif current!=before:raise ValueError('foreign installation object drift: '+name)
    # Exact objects and identity checked again before each removal; no rmtree,
    # following of symlinks or deletion of unknown children.
    for name in sorted(actual,key=lambda x:(x.count('/'),x),reverse=True):
        path=root/name;s=path.lstat();row=actual[name]
        if (s.st_ino,s.st_dev)!=(row['inode'],row['device']):raise ValueError('installation object changed before cleanup')
        if row['kind']=='directory':path.rmdir()
        else:
            if row['kind']=='file' and _digest(path)!=row['sha256']:raise ValueError('installation bytes changed before cleanup')
            path.unlink()

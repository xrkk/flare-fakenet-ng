"""Existing Windows-MCP execution plus the deployed Velo host coordinator.

Imports perform no target operations. This module does not implement chunks,
install a transport, create credentials, or replay an unknown execution.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import stat
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tomllib
from urllib.parse import urlparse
import uuid


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path,value):
    with Path(path).open('x',encoding='utf-8') as out:
        json.dump(value,out,ensure_ascii=False,indent=2);out.write('\n')


def psquote(value):
    if not isinstance(value,str) or any(ord(c)<32 for c in value):
        raise ValueError('invalid PowerShell literal')
    return "'"+value.replace("'","''")+"'"


class ChannelError(RuntimeError):
    pass


def push_vm_binding(result_path, result, spec):
    """Check the CLI's peer descriptor and its immutable guest cleanup binding."""
    entries = [entry.get('reference') for entry in result.get('evidence_index', [])
               if entry.get('role') == 'guest_cleanup']
    if len(entries) != 1 or not isinstance(entries[0], dict):
        raise ChannelError('Velo guest cleanup binding evidence missing')
    reference = entries[0]
    name = reference.get('name')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
        raise ChannelError('Velo cleanup binding reference invalid')
    path = Path(result_path).parent / (name + '.json')
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('not an immutable ordinary file')
        raw = path.read_bytes()
        after = path.lstat()
        fields = {'device': 'st_dev', 'inode': 'st_ino', 'mtime_ns': 'st_mtime_ns', 'size': 'st_size'}
        if any(getattr(before, field) != getattr(after, field) or
               reference.get(key) != getattr(after, field) for key, field in fields.items()):
            raise ValueError('binding evidence identity changed')
        if hashlib.sha256(raw).hexdigest() != reference.get('sha256'):
            raise ValueError('binding evidence bytes changed')
        response = json.loads(raw)
        terminal = response['terminal']
        if not isinstance(terminal, dict):
            raise ValueError('terminal is not an object')
        binding = terminal['binding']
        if (response.get('schema') != 'velo.transfer.guest.response.v1' or
                response.get('transfer_id') != spec['transfer_id'] or
                response.get('request_digest') != result.get('request_digest') or
                response.get('cleanup') != {'temporary_files_removed': True, 'workers_stopped': True} or
                response.get('local_phase') != 'DEST_RELEASED' or
                terminal.get('schema') != 'velo.transfer.guest_terminal.v1' or
                terminal.get('local_phase') != 'DEST_RELEASED' or
                terminal.get('destination') != result.get('destination_identity')):
            raise ValueError('cleanup response or terminal differs')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ChannelError('Velo cleanup binding evidence invalid') from None
    destination = result.get('destination_identity') or {}
    peer = destination.get('identity') or {}
    expected = spec['expected_vm_identity']
    if (destination.get('endpoint') != 'guest' or
            set(peer) != {'vm_uuid', 'boot_identity', 'policy_id'} or
            any(peer.get(key) != expected[key] for key in ('vm_uuid', 'boot_identity')) or
            not isinstance(peer.get('policy_id'), str) or not peer['policy_id'] or
            not isinstance(binding, dict) or
            any(binding.get(key) != expected[key] for key in ('vm_uuid', 'boot_identity', 'vm_epoch')) or
            binding.get('protocol_version') != 'velo.transfer.v1' or
            binding.get('transfer_id') != spec['transfer_id'] or
            binding.get('direction') != 'push' or
            binding.get('request_digest') != result.get('request_digest') or
            not isinstance(result.get('request_digest'), str) or
            not re.fullmatch(r'[0-9a-f]{64}', result['request_digest']) or
            binding.get('policy_id') != peer['policy_id']):
        raise ChannelError('Velo cleanup binding differs from fixed target or transfer')
    return binding


class ExistingWindowsChannel:
    def __init__(self,root,runtime,journal,*,powershell=None,run=None):
        self.root=Path(root);self.runtime=runtime;self.journal=Path(journal)
        self.journal.mkdir(parents=True,exist_ok=True)
        self.run=run or subprocess.run
        if powershell is None:
            config=tomllib.loads(Path(runtime['mcp_config_ref']).read_text())
            server=config['mcp_servers'][runtime['mcp_server']]
            if set(server)!={'url'} or urlparse(server['url']).username or urlparse(server['url']).query or urlparse(server['url']).fragment:
                raise ChannelError('existing Win10VmChannel does not support this configuration; preserve auth reference')
            # Reuse the product's existing client, not its historical default IP.
            directory=self.root/'test/mcp/acceptance'
            sys.path.insert(0,str(directory))
            spec=importlib.util.spec_from_file_location('acceptance_original_vm_helpers',directory/'helpers.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            powershell=module.Win10VmChannel(server['url']).powershell
        self.powershell=powershell

    def invoke(self,name,command,timeout):
        # An existing intent means an earlier call may already have executed.
        # Read-only Observe has a new name, never reissues this command.
        intent=self.journal/(name+'-intent.json')
        write_new(intent,{'operation':name,'command':command,'timeout':timeout})
        try:
            result=self.powershell(command,timeout=timeout)
        except BaseException as exc:
            write_new(self.journal/(name+'-unknown.json'),{'status':'unknown','error_type':type(exc).__name__,'original_error':str(exc),'replay':False})
            raise ChannelError('target outcome unknown; preserve original operation, use Observe') from None
        write_new(self.journal/(name+'-response.json'),result)
        if result.get('exit_code')!=0 or result.get('is_error'):
            raise ChannelError('target command rejected; original response preserved')
        return json.loads(result['output'])

    def identity(self):
        value=self.invoke('identity',
            "$ErrorActionPreference='Stop'; @{platform='windows';hostname=[Net.Dns]::GetHostName();vm_uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower()}|ConvertTo-Json -Compress",30)
        if value.pop('vm_uuid',None)!=self.runtime['transfer']['expected_vm_identity']['vm_uuid']:
            raise ChannelError('MCP and Velo refer to different VM identities')
        return value

    def transfer(self,name,direction,sources,destination,*,producer_reference):
        transfer=self.runtime['transfer']
        python=Path(transfer['python']);origin=Path(transfer['origin'])
        if (not python.is_file() or digest(python)!=transfer['python_sha256'] or
                not origin.is_file() or digest(origin)!=transfer['origin_sha256']):
            raise ChannelError('trusted Velo interpreter/module binding changed')
        if not Path(transfer['connection_profile']).is_file():
            raise ChannelError('existing protected Velo connection profile unavailable')
        spec={'schema':'velo.transfer.request.v1','direction':direction,
              'sources':sources,'destination_directory':destination,
              'connection_profile':transfer['connection_profile'],
              'expected_vm_identity':transfer['expected_vm_identity'],
              'evidence_context':{'producer_complete':True,'producer_quiescent':True,
                                  'references':[producer_reference]},
              'budget':transfer['budget'],'transfer_id':uuid.uuid4().hex}
        spec_path=(self.journal/(name+'-spec.json')).resolve();write_new(spec_path,spec)
        argv=[str(python),'-I','-B','-m','velo_transfer','--spec',str(spec_path)]
        write_new(self.journal/(name+'-intent.json'),{'argv':argv,'spec_sha256':digest(spec_path)})
        out_path=self.journal/(name+'-stdout.log');err_path=self.journal/(name+'-stderr.log')
        try:
            with out_path.open('xb') as out,err_path.open('xb') as err:
                completed=self.run(argv,cwd=str(origin.parent.parent),stdout=out,stderr=err,check=False)
        except BaseException as exc:
            write_new(self.journal/(name+'-unknown.json'),{'error_type':type(exc).__name__,'retry_authorized':False})
            raise ChannelError('Velo outcome unknown; keep original spec/ID and handle') from None
        write_new(self.journal/(name+'-exit.json'),{'returncode':completed.returncode})
        if completed.returncode!=0:
            raise ChannelError('Velo transfer incomplete/rejected; preserve original spec and result, no fallback')
        summary=json.loads(out_path.read_text(encoding='utf-8'))
        result_path=Path(summary['result_path'])
        result=json.loads(result_path.read_text(encoding='utf-8'))
        if (result.get('schema')!='velo.transfer.result.v1' or result.get('transfer_id')!=spec['transfer_id'] or
            result.get('direction')!=direction or result.get('phase')!='COMPLETE' or
            result.get('outcome')!='complete' or result.get('published_ever') is not True or
            result.get('destination_verified') is not True or result.get('cleanup')!={'host':True,'guest':True}):
            raise ChannelError('Velo complete/publish/verification/cleanup contract missing')
        if direction == 'push':
            push_vm_binding(result_path, result, spec)
        elif result.get('source_vm_identity') != transfer['expected_vm_identity']:
            raise ChannelError('Velo VM identity differs from fixed target')
        destination_identity=result.get('destination_identity') or {}
        if destination_identity.get('canonical_path')!=destination:
            raise ChannelError('Velo destination differs from the requested new batch')
        files=result.get('files') or []
        if not files or len({f['relative_path'].casefold() for f in files})!=len(files):
            raise ChannelError('Velo file set empty or duplicated')
        for item in files:
            path=Path(item['destination'] if direction=='pull' else item['source'])
            if not path.is_file() or path.stat().st_size!=item['size'] or digest(path)!=item['sha256']:
                raise ChannelError('Velo local bytes differ from original terminal result')
            if direction=='pull' and not path.resolve().is_relative_to(Path(destination).resolve()):
                raise ChannelError('Velo file destination escapes fixed batch')
        write_new(self.journal/(name+'-terminal.json'),{'result_path':str(result_path),'sha256':digest(result_path),'spec_path':str(spec_path)})
        return result

    def execute(self,request_path,request_sha,output_root,source_hashes,timeout):
        root=PureWindowsPath(self.runtime['source_root'])
        guest=root/'tools/acceptance_guest.py'
        if 'tools/acceptance_guest.py' not in source_hashes:
            raise ChannelError('guest entry not pinned')
        # Verify the fixed executable entry before invoking Python. The guest
        # then verifies all remaining source hashes before starting a core.
        command=("$ErrorActionPreference='Stop'; $entry="+psquote(str(guest))+"; "
                 "if((Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLower() -cne "+psquote(source_hashes['tools/acceptance_guest.py'])+"){throw 'guest entry source mismatch'}; "
                 "& "+psquote(self.runtime['python'])+" -B $entry --request "+psquote(request_path)+" --request-sha256 "+psquote(request_sha)+"; "
                 "$inner=$LASTEXITCODE; $result=Get-Content -LiteralPath "+psquote(str(PureWindowsPath(output_root)/'guest-result.json'))+" -Raw|ConvertFrom-Json; "
                 "@{returncode=$inner;process_exited=$result.receipt.cleanup.process_exit.exited;recovered=$result.receipt.cleanup.recovered}|ConvertTo-Json -Compress")
        return self.invoke('execute',command,timeout+120)

    def observe(self,output_root):
        # Deliberately read-only. A missing marker means unresolved, never retry.
        path=str(PureWindowsPath(output_root)/'guest-result.json')
        return self.invoke('observe-'+uuid.uuid4().hex,
            "$ErrorActionPreference='Stop'; Get-Content -LiteralPath "+psquote(path)+" -Raw",30)

    def multihost_probes(self,request_path,request_sha,output_root,source_hashes,timeout):
        entry=str(PureWindowsPath(self.runtime['source_root'])/'tools/acceptance_multihost.py')
        command=("$ErrorActionPreference='Stop'; $entry="+psquote(entry)+"; "
                 "if((Get-FileHash -LiteralPath $entry -Algorithm SHA256).Hash.ToLower() -cne "+psquote(source_hashes['tools/acceptance_multihost.py'])+"){throw 'MultiHost entry changed'}; "
                 "& "+psquote(self.runtime['python'])+" -B $entry --request "+psquote(request_path)+" --request-sha256 "+psquote(request_sha)+" --action probes; "
                 "$inner=$LASTEXITCODE; @{returncode=$inner;process_exited=$true}|ConvertTo-Json -Compress")
        # The guest's result is retained on disk; suppress its stdout JSON so
        # invoke reads exactly the outer completed-process observation.
        command=command.replace(" --action probes; "," --action probes | Out-Null; ")
        return self.invoke('multihost-probes',command,timeout)

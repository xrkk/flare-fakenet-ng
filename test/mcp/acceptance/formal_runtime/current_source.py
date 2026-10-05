"""Current-run metadata handoff from actual journals and bounded transports.

This authority is confined to this context's owned output. It is not an
independently sealed historical index, business admission, or guest stop proof.
"""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from .clients import FreshClient
from .context import checked_record, exact_path, read_json, _freeze
from .instance import ProtectedVm
from .producer import VmJournal, file_record
from .producer_source import resolve_indexed
from .source import require


def _transport_closed(client, context, kind):
    require(isinstance(client,FreshClient) and client.context.materials_sha256 == context.materials_sha256
            and client.context.evidence_root == context.evidence_root
            and client.vm is (kind == 'vm'), 'current source requires actual same-context Fresh transport')
    ledger=client.responsibility()
    require(ledger['audit_safe'] and ledger['host_writers_ended'],
            'current source transport audit/writer closure unresolved')
    witnesses=[]
    # Re-read actual terminal/completion bytes, not a caller-supplied stopped flag.
    for entry in list(client.calls.values()):
        directory=exact_path(str(entry['directory']))
        require(directory.parent == context.evidence_root/'transport'/kind,
                'current source transport evidence outside exact owner')
        terminal=directory/'call-terminal.json'
        require(read_json(terminal) == entry['record'], 'current source transport terminal changed')
        witnesses.append(file_record(terminal))
        for completion in entry['record'].get('transport_completions',[]):
            require(completion.get('local_writer_ended') is True and isinstance(completion.get('completion'),str),
                    'current source actual bounded completion missing')
            path=exact_path(completion['completion'])
            require(path.is_relative_to(directory), 'current source transport completion escape')
            value=read_json(path)
            require(value.get('local_writer_ended') is True and all(value.get(key) == completion.get(key)
                    for key in ('status','client_pid','sent')), 'current source bounded completion changed or unclosed')
            witnesses.append(file_record(path))
    return witnesses


class CurrentAuthority:
    def __init__(self, context, protected_vm, service_client):
        self.context=context.revalidate()
        require(isinstance(protected_vm,ProtectedVm) and isinstance(protected_vm.journal,VmJournal)
                and protected_vm.context.materials_sha256 == context.materials_sha256
                and protected_vm.root == context.evidence_root, 'current source requires actual same-context ProtectedVm')
        journal=protected_vm.journal
        require(journal.context.materials_sha256 == context.materials_sha256 and journal.audit_safe,
                'current source VM witness audit unresolved')
        self.witnesses=_transport_closed(protected_vm.client.client,context,'vm')
        self.witnesses.extend(_transport_closed(service_client,context,'service'))
        self.root=context.evidence_root
        require(self.root.is_dir(), 'current source original output absent')
        rows={}
        for path in sorted(self.root.rglob('*.json')):
            path=exact_path(str(path))
            require(path.is_file(), 'current source metadata is not a regular file')
            relative=path.relative_to(self.root).as_posix()
            record=file_record(path)
            rows[relative]=_freeze(dict(record,path=relative))
        self.rows=MappingProxyType(rows)
        self.index_record=None  # Deliberately not a self-certified historical index.
        require(journal.calls, 'current source actual VM journal empty')
        journal_ids=set(journal.calls)
        actual_ids={Path(relative).stem for relative in rows if relative.startswith('VM-final-intents/')
                    and len(Path(relative).parts) == 2}
        require(actual_ids == journal_ids, 'current source journal/disk dispatch set differs')
        for key,call in journal.calls.items():
            record=call['intent'].get('record')
            require(record is not None and record['path'] == str(self.root/'VM-final-intents'/(key+'.json')),
                    'current source actual immutable intent record absent')
            checked_record(record)
            self.witnesses.append(record)
            terminal=self.root/'VM-final-terminals'/(key+'.json')
            require(read_json(terminal) == call['terminal'] and 'finished_monotonic' in call['terminal'],
                    'current source VM dispatch terminal changed or pending')
            self.witnesses.append(file_record(terminal))

    def read(self,path):
        path=exact_path(str(path))
        require(path.is_relative_to(self.root), 'current source metadata reference escape')
        row=self.rows.get(path.relative_to(self.root).as_posix())
        require(row is not None, 'current source metadata absent from closed snapshot')
        record={'path':str(path),'size':row['size'],'sha256':row['sha256']}
        checked_record(record)
        self.witnesses.append(record)
        return read_json(path)

    def frozen_dependency(self,path,sha256):
        path=exact_path(str(path))
        context=self.context
        records=[file_record(context.materials_path),dict(context.materials['plan'])]
        matched=[record for record in records if record['path'] == str(path) and record['sha256'] == sha256]
        require(len(matched) == 1 and (path != context.materials_path or sha256 == context.materials_sha256),
                'current source frozen dependency is not its independently pinned input')
        checked_record(matched[0])
        self.witnesses.append(matched[0])
        return read_json(path)


def resolve_current(context, protected_vm, service_client):
    authority=CurrentAuthority(context,protected_vm,service_client)
    binding=resolve_indexed(authority)
    values=dict(binding.values)
    values.update(derived_from_actual_immutable_source=False,
                  derived_from_current_original_execution=True,
                  historical_source_authority=False, transport_host_writers_ended=True,
                  guest_business_writer_closure_not_granted=True)
    from .source import SourceBinding
    return authority,SourceBinding(_freeze(values))


def resolve_current_capture(context, protected_vm, service_client):
    """Actual closed journals for a row's readonly query, without final export."""
    authority = CurrentAuthority(context, protected_vm, service_client)
    return authority, resolve_indexed(authority, capture_only=True)

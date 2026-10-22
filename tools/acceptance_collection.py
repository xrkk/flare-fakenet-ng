"""Closed original-file index for the existing file-only REMnux SDK."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):h.update(block)
    return h.hexdigest()


def write_index(output,request_sha256):
    output=Path(output)
    rows=[]
    for path in sorted(output.rglob('*')):
        if path.is_symlink():raise ValueError('original export contains symlink')
        if path.is_file():
            rows.append({'relative_path':path.relative_to(output).as_posix(),
                         'size':path.stat().st_size,'sha256':digest(path)})
    value={'schema':'fakenet.closed-originals.v1','output_root':str(output),
           'request_sha256':request_sha256,'files':rows}
    with (output/'export-index.json').open('x',encoding='utf-8') as out:
        json.dump(value,out,indent=2)
    return value


def validate_index(value,output,request_sha256):
    if (value.get('schema')!='fakenet.closed-originals.v1' or value.get('output_root')!=output or
        value.get('request_sha256')!=request_sha256):
        raise ValueError('original export request/root mismatch')
    rows=value.get('files');seen=set();total=0
    if not isinstance(rows,list) or not rows or len(rows)>10000:raise ValueError('invalid original export count')
    for row in rows:
        rel=PurePosixPath(row['relative_path'])
        if (not rel.parts or rel.is_absolute() or '..' in rel.parts or str(rel)!=row['relative_path'] or
            str(rel) in seen or str(rel)=='export-index.json' or
            type(row['size']) is not int or row['size']<0 or
            len(row['sha256'])!=64 or any(c not in '0123456789abcdef' for c in row['sha256'])):
            raise ValueError('invalid/duplicate original export member')
        seen.add(str(rel));total+=row['size']
    if total>1<<30:raise ValueError('original export exceeds existing SDK budget')
    return rows


def collect(channel,name,remote_output,request_sha256,destination):
    # A caller must first observe its exact producer job EXITED. Never collect
    # while it is active, unknown or forcibly stopped.
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    index=destination.parent/(name+'-export-index.json')
    channel.get(name+'-index',channel.relative(remote_output+'/export-index.json'),index)
    value=json.loads(index.read_text());rows=validate_index(value,remote_output,request_sha256)
    for number,row in enumerate(rows):
        path=destination.joinpath(*PurePosixPath(row['relative_path']).parts)
        path.parent.mkdir(parents=True,exist_ok=True)
        channel.get(name+'-%04d'%number,channel.relative(remote_output+'/'+row['relative_path']),path)
        if path.stat().st_size!=row['size'] or digest(path)!=row['sha256']:
            raise ValueError('collected original differs from closed index')
    return value

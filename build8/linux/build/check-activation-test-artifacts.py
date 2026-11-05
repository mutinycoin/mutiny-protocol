#!/usr/bin/env python3
"""Exact public linked-artifact negative scan; source/Cargo/reachability separate."""
import argparse, hashlib, json, os, pathlib, stat
MARKERS=['BUILD8-PRIVATE-ACTIVATION-TEST-V1', 'mutiny-activation-test', 'SoftwareMakeCredential', 'EmptyAuthEndpoint', 'PolicySecretSimulatorEndpoint', 'PolicySimulatorSet', 'PUBLIC-SELECTED-TEST-ACTIVATION-GENESIS-V1', 'selected_genesis_native_scope_cancel_context_and_all_classes', 'PRIVATE-TRUSTED-TEST-ACTIVATION-MODEL-V1', 'genuine_executed_scope_private_model_cancel_context_and_all_classes']
parser=argparse.ArgumentParser()
parser.add_argument('--artifact',required=True)
parser.add_argument('--sha256',required=True)
parser.add_argument('--source-manifest-sha256',required=True)
args=parser.parse_args()
for value in (args.sha256,args.source_manifest_sha256):
    if len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('exact lowercase SHA-256 pin required')
p=pathlib.Path(args.artifact)
if not p.is_absolute() or '..' in p.parts:raise ValueError('exact absolute artifact path')
for route in [*reversed(p.parents),p]:
    meta=route.lstat()
    if stat.S_ISLNK(meta.st_mode) or getattr(meta,'st_file_attributes',0)&0x400:
        raise ValueError('reparse/symlink artifact route')
initial=p.stat()
if not stat.S_ISREG(initial.st_mode) or initial.st_nlink!=1 or initial.st_size>2*1024**3:
    raise ValueError('bounded plain single-link linked artifact required')
needles=[(marker,encoding,marker.encode(encoding)) for marker in MARKERS for encoding in ('ascii','utf-16-le')]
maximum=max(len(raw) for _,_,raw in needles)
digest=hashlib.sha256();tail=b'';hits=set()
with p.open('rb') as f:
    opened=os.fstat(f.fileno())
    if (opened.st_dev,opened.st_ino,opened.st_size)!=(initial.st_dev,initial.st_ino,initial.st_size):raise ValueError('artifact open identity changed')
    while block:=f.read(1024*1024):
        digest.update(block);window=tail+block
        for marker,encoding,needle in needles:
            if needle in window:hits.add((marker,encoding))
        tail=window[-(maximum-1):]
    final=os.fstat(f.fileno())
if (final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns)!=(initial.st_dev,initial.st_ino,initial.st_size,initial.st_mtime_ns):
    raise ValueError('artifact changed during scan')
if digest.hexdigest()!=args.sha256:raise ValueError('actual artifact hash mismatch')
if hits:raise ValueError('private activation marker present: '+json.dumps(sorted(hits)))
print(json.dumps({'status':'PASS exact artifact marker exclusion ONLY','artifact':str(p),'sha256':digest.hexdigest(),
    'source_manifest_sha256':args.source_manifest_sha256,'bytes':initial.st_size,'complete_markers':len(MARKERS),
    'encodings':['ascii','utf-16-le'],'hits':[],'cargo_graph':'SEPARATE REQUIRED','runtime':'NO CREDIT'}))

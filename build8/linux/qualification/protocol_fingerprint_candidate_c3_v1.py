"""Explicitly unfrozen source-only candidate; never supplies authentic V2 bindings.

Inspect is read-only. Generate creates one NEW output directory and never overwrites
an original, V9, candidate or snapshot. Native lock files commit their complete raw
member inventories, not a guessed .c/.h sweep. No production ceremony API exists.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import subprocess

NETWORK = 0x4D555401
DOMAIN = b'MUTINY-BUILD8-PROTOCOL-FINGERPRINT-V1'
SCOPE = 'build/protocol-rule-candidate-scope-v2.json'
OUTPUT_NAME = 'PROTOCOL-FINGERPRINT-CANDIDATE-C3-INCOMPLETE-V1.json'
BINDINGS = {'genesis-class-v2', 'endorsement-root-set-v2', 'endorsement-identity-classes-v1', 'accepted-pcr-profile-set-v1'}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field: '+key)
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs)

def relative(name):
    p = PurePosixPath(name)
    if '\\' in name or not name or p.is_absolute() or PureWindowsPath(name).drive or ':' in name or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('unsafe relative source path: '+name)
    return p

def checked(root, name):
    relative(name)
    path = root / name
    for part in [path, *list(path.parents)[:len(PurePosixPath(name).parts)-1]]:
        st = part.lstat()
        if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
            raise ValueError('symlink/reparse source: '+name)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('source is not a singly linked regular file: '+name)
    if not path.resolve().is_relative_to(root):
        raise ValueError('source escaped workspace: '+name)
    return path.read_bytes()

def directory_files(root, prefix):
    relative(prefix)
    base = root / prefix
    if base.is_symlink() or getattr(base.lstat(), 'st_file_attributes', 0) & 0x400:
        raise ValueError('unsafe source directory: '+prefix)
    result = []
    for folder, dirs, files in os.walk(base, followlinks=False):
        for leaf in dirs:
            p = Path(folder) / leaf
            if p.is_symlink() or getattr(p.lstat(), 'st_file_attributes', 0) & 0x400:
                raise ValueError('unsafe directory: '+str(p))
        result += [(Path(folder)/leaf).relative_to(root).as_posix() for leaf in files]
    return sorted(result)

def directory_inventory(root, prefix, files):
    directories = []
    for folder, dirs, _ in os.walk(root/prefix, followlinks=False):
        directories += [(Path(folder)/leaf).relative_to(root).as_posix() for leaf in dirs]
    return dict(files=files, directories=sorted(directories))

def head(major, n):
    if not 0 <= n <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError('CBOR integer range')
    for bound, code, width in [(24, None, 0), (256, 24, 1), (65536, 25, 2), (2**32, 26, 4), (2**64, 27, 8)]:
        if n < bound:
            return bytes([(major << 5) | n]) if code is None else bytes([(major << 5) | code])+n.to_bytes(width, 'big')
    raise ValueError('CBOR range')

def manifest(entries):
    if not 1 <= len(entries) <= 512:
        raise ValueError('manifest count')
    raw = head(4, 3)+head(0, 1)+head(0, NETWORK)+head(4, len(entries))
    prior = None
    for name, digest in entries:
        name = name.encode('ascii')
        if not 1 <= len(name) <= 128 or any(not 0x21 <= b <= 0x7e for b in name) or (prior is not None and prior >= name):
            raise ValueError('manifest name/order')
        if len(digest) != 32:
            raise ValueError('manifest hash')
        raw += head(4, 2)+head(2, len(name))+name+head(2, 32)+digest
        prior = name
    if len(raw) > 128*1024:
        raise ValueError('manifest size')
    return raw

def collect(root):
    scope_raw = checked(root, SCOPE)
    scope = parse_json(scope_raw)
    if scope.get('schema') != 'BUILD8-RULE-CANDIDATE-SCOPE-V2' or {r['name'] for r in scope['unresolved_bindings']} != BINDINGS or len(scope['unresolved_bindings']) != 4 or not all(isinstance(r['reason'], str) and r['reason'] for r in scope['unresolved_bindings']):
        raise ValueError('exact four missing authentic bindings/reasons required')
    artifacts = {SCOPE: canonical_json(scope)}
    frozen = {SCOPE: sha(scope_raw)}
    inventories = {}
    tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode('utf-8').split('\0'))
    def add(name, json_mode=False):
        raw = checked(root, name)
        frozen[name] = sha(raw)
        normalized = canonical_json(parse_json(raw)) if json_mode else raw.replace(b'\r\n', b'\n')
        if name in artifacts:
            raise ValueError('duplicate artifact: '+name)
        artifacts[name] = normalized
    for prefix in scope['source_directories']:
        names = directory_files(root, prefix)
        inventories[prefix] = directory_inventory(root, prefix, names)
        for name in names:
            if name.endswith('.rs'):
                if name not in tracked:
                    raise ValueError('untracked Rust source requires explicit integration before inventory: '+name)
                add(name)
    for prefix in scope['full_local_build_directories']:
        names = directory_files(root, prefix)
        inventories[prefix] = directory_inventory(root, prefix, names)
        for name in names:
            add(name)
    for name in scope['metadata']+scope['normative_specs']:
        add(name, name.endswith('.json'))
    for closure in scope['native_closures']:
        lock_name, prefix = closure['lock'], closure['root']
        add(lock_name, True)
        lock = parse_json(checked(root, lock_name))
        hashes = lock['sources'][closure['entry']]['files'] if 'entry' in closure else lock['files']
        expected = {prefix+'/'+name for name in hashes}
        extras = {prefix+'/'+name for name in closure.get('extra_files', [])}
        names = directory_files(root, prefix)
        inventories[prefix] = directory_inventory(root, prefix, names)
        if set(names) != expected | extras:
            raise ValueError('native closure inventory mismatch: '+prefix)
        for name, digest in hashes.items():
            relative(name)
            full = prefix+'/'+name
            actual = sha(checked(root, full))
            if actual != digest:
                raise ValueError('native source lock mismatch: '+full)
            frozen[full] = actual
        for name in sorted(extras):
            add(name)
    registry = parse_json(checked(root, 'spec/DOMAIN-REGISTRY-V1.json'))
    frozen['spec/DOMAIN-REGISTRY-V1.json'] = sha(checked(root, 'spec/DOMAIN-REGISTRY-V1.json'))
    rules = {k: v for k, v in registry.items() if k not in ('schema','status','complete_protocol_fingerprint_ready','remaining')}
    artifacts['rules/domain-registry.json'] = canonical_json(rules)
    forbidden = {'physical-admission-trust-roots-v1', *[r['name'] for r in scope['unresolved_bindings']]}
    if forbidden & set(artifacts):
        raise ValueError('unresolved/legacy binding entered source candidate')
    # Validate limits even in inspect mode; no fingerprint/output is formed there.
    manifest([(n, bytes.fromhex(sha(b))) for n, b in sorted(artifacts.items())])
    frozen[self_name(root)] = sha(checked(root, self_name(root)))
    return artifacts, frozen, inventories, scope['unresolved_bindings']

def self_name(root):
    return Path(__file__).resolve().relative_to(root).as_posix()

def inspect(root):
    artifacts, frozen, inventories, missing = collect(root)
    return dict(schema='BUILD8-SOURCE-INVENTORY-C3-V1', qualification_status='INCOMPLETE',
        artifact_count=len(artifacts), files={n: dict(sha256=sha(b), bytes=len(b)) for n,b in sorted(artifacts.items())},
        raw_source_sha256=frozen, directory_inventories=inventories, missing_bindings=missing,
        fingerprint_generated=False, locked_for_genesis=False, genesis_sealed=False)

def generate(root, output):
    # Deliberately NEW directory. It cannot be the workspace, a scanned input, an
    # existing evidence directory or an original checkout. Only owned child outputs.
    output = output.absolute()
    if output != output.resolve(strict=False):
        raise ValueError('output path must be canonical without aliases or parent traversal')
    if output.exists() or output.is_symlink() or not output.parent.resolve().is_relative_to(root):
        raise ValueError('output must be new inside this explicit workspace')
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError('unsafe output parent')
    for parent in [output.parent, *output.parent.parents]:
        if parent == root:
            break
        if parent.is_symlink() or getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('reparse/aliased output ancestor')
    artifacts, frozen, inventories, missing = collect(root)
    for prefix in inventories:
        if output.is_relative_to(root/prefix) or (root/prefix).is_relative_to(output):
            raise ValueError('output overlaps source closure')
    entries = [(name, bytes.fromhex(sha(raw))) for name,raw in sorted(artifacts.items())]
    encoded = manifest(entries)
    report = dict(schema='BUILD8-PROTOCOL-FINGERPRINT-CANDIDATE-V1', candidate_id=output.name,
        qualification_status='INCOMPLETE', candidate_only=True, locked_for_genesis=False, genesis_sealed=False,
        instance_identities_included=False, production_authorized=False, unresolved_bindings=missing,
        manifest_hex=encoded.hex(), fingerprint=sha(DOMAIN+b'\0'+encoded), state_root_version=2,
        generator_sha256=frozen[self_name(root)], source_snapshot_sha256=sha(canonical_json(frozen)),
        files={name:dict(sha256=sha(raw),snapshot='artifacts/'+sha(raw)) for name,raw in sorted(artifacts.items())})
    output.mkdir()
    snapshots = output/'artifacts'; snapshots.mkdir()
    # Content-identical artifacts may share a snapshot; all writes remain create-new.
    for raw in artifacts.values():
        path=snapshots/sha(raw)
        if path.exists():
            if path.read_bytes()!=raw:raise ValueError('snapshot collision')
        else:
            with path.open('xb') as f:f.write(raw)
    _, again, dirs, _ = collect(root)
    if again != frozen or dirs != inventories:
        raise ValueError('source changed during snapshots; partial output preserved')
    with (output/'SOURCE-FREEZE.json').open('x',encoding='utf-8') as f:
        json.dump(dict(raw_source_sha256=frozen,directory_inventories=inventories),f,sort_keys=True,indent=2);f.write('\n')
    with (output/OUTPUT_NAME).open('x',encoding='utf-8') as f:
        json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
    _, final, final_dirs, _ = collect(root)
    if final!=frozen or final_dirs!=inventories:
        raise ValueError('source changed after output; attempted candidate preserved, not qualified')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--inspect',action='store_true')
    p.add_argument('--output-dir',type=Path)
    args=p.parse_args()
    root=args.workspace.absolute()
    if root.is_symlink() or root.resolve()!=root or not (root/'.git').exists():
        raise ValueError('explicit non-aliased Git workspace required')
    if args.inspect == (args.output_dir is not None):
        p.error('choose read-only --inspect OR new --output-dir')
    result=inspect(root) if args.inspect else generate(root,args.output_dir)
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':
    main()

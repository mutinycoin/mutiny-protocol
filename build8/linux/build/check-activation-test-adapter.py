#!/usr/bin/env python3
"""Source guard only. Native Cargo/linked-artifact exclusion remains separate."""
import pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
owned=root/'node/src/activation_test_adapter_v1'
target=root/'node/tests/activation_private_adapter_v1.rs'
assert owned.is_dir() and target.is_file()
actual=target.read_text(encoding='utf-8').replace('\r\n','\n')
assert actual.count('#[path="../src/activation_test_adapter_v1/mod.rs"]')==1
assert actual.count('mod activation_test_adapter_v1;')==1
for path in (root/'node/src').rglob('*.rs'):
    if owned in path.parents: continue
    text=path.read_text(encoding='utf-8')
    assert 'activation_test_adapter_v1' not in text, f'normal Node include/export: {path}'
manifest=(root/'node/Cargo.toml').read_text(encoding='utf-8')
assert 'activation-test-adapter' not in manifest and 'activation_test_adapter' not in manifest
markers=['BUILD8-PRIVATE-ACTIVATION-TEST-V1', 'mutiny-activation-test', 'SoftwareMakeCredential', 'EmptyAuthEndpoint', 'PolicySecretSimulatorEndpoint', 'PolicySimulatorSet', 'PUBLIC-SELECTED-TEST-ACTIVATION-GENESIS-V1', 'selected_genesis_native_scope_cancel_context_and_all_classes', 'PRIVATE-TRUSTED-TEST-ACTIVATION-MODEL-V1', 'genuine_executed_scope_private_model_cancel_context_and_all_classes']
for path in (root/'node/src').rglob('*.rs'):
    if owned in path.parents: continue
    text=path.read_text(encoding='utf-8')
    assert not any(marker in text for marker in markers),f'normal activation factory/content: {path}'
for tree in ('wallet-core/src','desktop/src','release-signer/src'):
    for path in (root/tree).rglob('*.rs'):
        text=path.read_text(encoding='utf-8')
        assert 'activation_test_adapter_v1' not in text, f'normal private activation include: {path}'
        assert not any(marker in text for marker in markers), f'normal private activation producer: {path}'
print('PASS source-only activation adapter TEST inclusion guard; Cargo/artifacts UNCHECKED')

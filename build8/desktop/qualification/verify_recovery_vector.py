"""Independent public fixture CBOR/Ed25519 check. Never accepts real secrets."""
import hashlib, json
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

v=json.loads(Path(__file__).with_name('recovery-vector-v1.json').read_text())
loss=hashlib.sha256(b'MUTINY-BUILD8-SUPERVISED-HARDWARE-LOSS-V1\0'+cbor2.dumps([[bytes([1])*32,0]],canonical=True)).digest()
body=[1,0x4d555401,bytes([4])*32,bytes([5])*32,0,bytes([1])*32,
      bytes([2])*32,bytes([3])*32,1,bytes([1])*32,0,bytes([70])*32,
      bytes([80])*32,bytes([6])*32,bytes([2])*33,1,1,loss,1]
encoded=cbor2.dumps(body,canonical=True)
assert encoded.hex()==v['body_cbor']
digest=hashlib.sha256(b'MUTINY-BUILD8-BOOTSTRAP-RECOVERY-V1\0'+encoded).digest()
assert digest.hex()==v['signing_digest']
key=Ed25519PrivateKey.from_private_bytes(bytes([0x42])*32)
assert key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()==v['public_key']
signature=key.sign(digest)
assert signature.hex()==v['signature']
assert cbor2.dumps([encoded,signature],canonical=True).hex()==v['certificate_cbor']
key.public_key().verify(signature,digest)
print('PASS: independent canonical CBOR, domain hash, public key and Ed25519 signature fixture')

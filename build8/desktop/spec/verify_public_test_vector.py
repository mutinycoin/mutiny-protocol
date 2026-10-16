"""Independent known-public test vector only; accepts no wallet/seed input."""
import hashlib, hmac, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

phrase = " ".join(["abandon"] * 23 + ["art"])
seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic", 2048)
derived = hmac.digest(b"ed25519 seed", seed, "sha512")
for index in [44, 1297437697, 0, 0, 0]:
    derived = hmac.digest(derived[32:], b"\0" + derived[:32] + (index | 0x80000000).to_bytes(4, "big"), "sha512")
public = Ed25519PrivateKey.from_private_bytes(derived[:32]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def identity(domain):
    return hashlib.sha256(domain + bytes.fromhex("4d555401") + public).hexdigest()
print(json.dumps({"test_entropy": "00"*32, "owner_public_key": public.hex(), "address_id": identity(b"MUTINY-BUILD8-ADDRESS-V1\0"), "account_id": identity(b"MUTINY-BUILD8-ACCOUNT-V1\0")}, indent=2))

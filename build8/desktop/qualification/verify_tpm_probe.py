"""Independent public TPM transcript verifier; this does not establish EK trust."""
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

class Reader:
    def __init__(self, data): self.data, self.pos = data, 0
    def take(self, n):
        if self.pos+n > len(self.data): raise ValueError('truncated')
        b=self.data[self.pos:self.pos+n]; self.pos+=n; return b
    def uint(self,n): return int.from_bytes(self.take(n),'big')
    def blob(self): return self.take(self.uint(2))
    def end(self):
        if self.pos != len(self.data): raise ValueError('trailing data')

def public(data, restricted):
    r=Reader(data)
    assert r.uint(2)==0x23 and r.uint(2)==0xb
    assert r.uint(4)==(0x50472 if restricted else 0x40472)
    assert r.blob()==b'' and r.uint(2)==0x10
    assert r.uint(2)==0x18 and r.uint(2)==0xb
    assert r.uint(2)==3 and r.uint(2)==0x10
    x,y=r.blob(),r.blob(); r.end()
    assert len(x)==len(y)==32
    return ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'),int.from_bytes(y,'big'),ec.SECP256R1()).public_key()

def verify(report):
    ak=bytes.fromhex(report['ak_public']); voter=bytes.fromhex(report['voting_public'])
    pub=public(ak,True); public(voter,False)
    nonce=bytes.fromhex(report['nonce']); assert len(nonce)==32
    signer=None
    for field, kind in [('quote',0x8018),('certify',0x8017)]:
        data=bytes.fromhex(report[field]); r=Reader(data)
        assert r.uint(4)==0xff544347 and r.uint(2)==kind
        current_signer=r.blob()
        assert len(current_signer)==34 and current_signer[:2]==b'\x00\x0b'
        if signer is not None: assert signer==current_signer
        signer=current_signer
        assert r.blob()==nonce
        r.take(8+4+4); assert r.uint(1)==1; r.take(8)
        if field=='quote':
            assert r.uint(4)==1 and r.uint(2)==0xb
            assert r.take(r.uint(1))==bytes([149,0,0])
            digests=[bytes.fromhex(x) for x in report['pcr_digests']]
            assert len(digests)==4 and all(len(x)==32 for x in digests)
            assert r.blob()==hashlib.sha256(b''.join(digests)).digest()
        else:
            assert r.blob()==b'\x00\x0b'+hashlib.sha256(voter).digest()
            assert len(r.blob())==34
        r.end()
        s=Reader(bytes.fromhex(report[field+'_signature']))
        assert s.uint(2)==0xb
        a,b=s.blob(),s.blob(); s.end()
        assert len(a)==len(b)==32
        signature=utils.encode_dss_signature(int.from_bytes(a,'big'),int.from_bytes(b,'big'))
        pub.verify(signature,data,ec.ECDSA(hashes.SHA256()))

if __name__=='__main__':
    root=Path(__file__).resolve().parent
    report=json.loads((root/'node-a-tpm-proof-probe.json').read_text(encoding='utf-8-sig'))
    verify(report)
    negative=0
    for field in ['nonce','ak_public','voting_public','quote','certify','quote_signature','certify_signature']:
        bad=dict(report); raw=bytearray.fromhex(bad[field]); raw[-1]^=1; bad[field]=raw.hex()
        try: verify(bad)
        except Exception: negative+=1
        else: raise AssertionError('tamper accepted: '+field)
    result={'schema':'BUILD8-INDEPENDENT-TPM-PROBE-V1','result':'PASS','negative_checks':negative,
            'quote_and_certified_key_binding':True,'attestation_qualified':False,
            'source_sha256':hashlib.sha256((root/'node-a-tpm-proof-probe.json').read_bytes()).hexdigest()}
    (root/'node-a-tpm-independent-probe.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

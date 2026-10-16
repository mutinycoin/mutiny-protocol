"""Verify the public manufacturer chain, without claiming revocation status."""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

ROOT=Path(__file__).resolve().parent
PINS={
 'stmtpmekint06.crt':'9343d2d7f3c8708526e6f224563bebda23f534c518f2a1a421ebcce01557247c',
 'stmtpmekroot.crt':'f8e37a86b689a20a6cc0c40cc3f81fb130fa9f44ce7ffa60d62590aaf87273a9',
 'gstpmroot.crt':'f27bf02c6e00c73d915eeb6a6a2f5fbf0c31ae0393149e6b5c31e41b113841c3',
}

def verify():
    inv=json.loads((ROOT/'node-a-tpm-inventory.json').read_text(encoding='utf-8-sig'))
    leaf=base64.b64decode(inv['manufacturer_certificates'][0]['public_certificate_der_base64'],validate=True)
    ders=[leaf]
    for name,pin in PINS.items():
        data=(ROOT/'public-tpm-ca'/name).read_bytes()
        assert hashlib.sha256(data).hexdigest()==pin, 'unrecognized CA file'
        ders.append(data)
    certs=[x509.load_der_x509_certificate(d) for d in ders]
    now=datetime.now(timezone.utc)
    for i,cert in enumerate(certs):
        assert cert.not_valid_before_utc<=now<=cert.not_valid_after_utc
        issuer=certs[min(i+1,len(certs)-1)]
        assert cert.issuer==issuer.subject
        key=issuer.public_key(); assert isinstance(key,rsa.RSAPublicKey)
        assert key.key_size>=2048 and cert.signature_hash_algorithm.name in ('sha256','sha384','sha512')
        key.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
        bc=cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        ku=cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if i==0:
            assert not bc.ca and ku.key_encipherment and not ku.key_cert_sign
            eku=cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            assert ObjectIdentifier('2.23.133.8.1') in eku
        else:
            assert bc.ca and ku.key_cert_sign
            assert bc.path_length is None or bc.path_length>=i-1
        allowed_critical={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,
                          ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
        for extension in cert.extensions:
            if extension.critical and extension.oid==ExtensionOID.CERTIFICATE_POLICIES:
                # This pinned intermediate declares only anyPolicy. It adds no
                # narrower application policy; EK usage is checked on the leaf.
                assert [p.policy_identifier.dotted_string for p in extension.value]==['2.5.29.32.0']
                allowed_critical.add(ExtensionOID.CERTIFICATE_POLICIES)
        assert all(not e.critical or e.oid in allowed_critical for e in cert.extensions)
    result={'schema':'BUILD8-EK-CRYPTOGRAPHIC-CHAIN-V1','cryptographic_chain':'PASS',
            'checked_at_utc':now.isoformat(),'certificates':len(certs),
            'online_revocation_status':'UNAVAILABLE_NO_CERTIFICATE_ENDPOINTS',
            'genesis_trust_policy_locked':False,'attestation_qualified':False,
            'manufacturer_ca_source':'https://www.st.com/resource/en/technical_note/tn1330-st-trusted-platform-module-tpm-endorsement-key-ek-certificates-stmicroelectronics.pdf',
            'certificate_hashes':[hashlib.sha256(d).hexdigest() for d in ders]}
    (ROOT/'node-a-ek-cryptographic-chain.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__': verify()

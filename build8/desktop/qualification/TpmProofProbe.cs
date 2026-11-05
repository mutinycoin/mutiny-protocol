// Uses only fresh transient child keys. Never clears, evicts, changes hierarchy
// authorization, writes NV, exports private key material, or changes boot policy.
// This capability probe is not a production admission certificate.
using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Web.Script.Serialization;
using Tpm2Lib;

class TpmProofProbe {
    static byte[] Random(int n) { var b=new byte[n]; using(var r=RandomNumberGenerator.Create()) r.GetBytes(b); return b; }
    static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }
    static TpmPublic Template(bool restricted) {
        return new TpmPublic(TpmAlgId.Sha256,
            ObjectAttr.FixedTPM|ObjectAttr.FixedParent|ObjectAttr.SensitiveDataOrigin|
            ObjectAttr.UserWithAuth|ObjectAttr.NoDA|ObjectAttr.Sign|
            (restricted ? ObjectAttr.Restricted : 0), new byte[0],
            new EccParms(new SymDefObject(), new SchemeEcdsa(TpmAlgId.Sha256),
                EccCurve.NistP256, new NullKdfScheme()), new EccPoint());
    }
    static int Main(string[] args) {
        if(args.Length!=1) { Console.Error.WriteLine("Expected public result path"); return 2; }
        var report=new Dictionary<string,object>();
        report["schema"]="BUILD8-TPM-PROOF-PROBE-V1";
        report["attestation_qualified"]=false;
        report["private_material_persisted"]=false;
        var handles=new List<TpmHandle>();
        var secrets=new List<byte[]>();
        var device=new TbsDevice(false);
        Tpm2 tpm=null;
        string stage="connect";
        try {
            device.Connect(); tpm=new Tpm2(device,Behavior.Strict);
            var parent=new TpmHandle(0x81000009u);
            byte[] name,qualified;
            stage="read_storage_parent";
            var parentPub=tpm.ReadPublic(parent,out name,out qualified);
            if((parentPub.objectAttributes & (ObjectAttr.FixedTPM|ObjectAttr.FixedParent|ObjectAttr.Restricted|ObjectAttr.Decrypt)) !=
                (ObjectAttr.FixedTPM|ObjectAttr.FixedParent|ObjectAttr.Restricted|ObjectAttr.Decrypt))
                throw new Exception("Storage parent attributes rejected");
            var auth=new byte[2][]; var pubs=new TpmPublic[2];
            for(int i=0;i<2;i++) {
                stage=i==0 ? "create_fresh_ak" : "create_fresh_voting_probe";
                auth[i]=Random(32); secrets.Add(auth[i]);
                CreationData creation; byte[] creationHash; TkCreation ticket;
                var priv=tpm[new AuthValue()].Create(parent,new SensitiveCreate(auth[i],new byte[0]),
                    Template(i==0),new byte[0],new PcrSelection[0],out pubs[i],out creation,out creationHash,out ticket);
                handles.Add(tpm[new AuthValue()].Load(parent,priv,pubs[i]));
                report[i==0?"ak_public":"voting_public"]=Hex(pubs[i].GetTpmRepresentation());
            }
            var nonce=Random(32); report["nonce"]=Hex(nonce);
            var selection=new[]{new PcrSelection(TpmAlgId.Sha256,new byte[]{149,0,0})};
            PcrSelection[] selected; Tpm2bDigest[] digests;
            stage="pcr_read";
            report["pcr_counter"]=tpm.PcrRead(selection,out selected,out digests);
            report["pcr_digests"]=Array.ConvertAll(digests,x=>Hex(x.buffer));
            stage="quote";
            ISignatureUnion signature;
            var quote=tpm[new AuthValue(auth[0])].Quote(handles[0],nonce,new SchemeEcdsa(TpmAlgId.Sha256),selection,out signature);
            report["quote"]=Hex(quote.GetTpmRepresentation());
            report["quote_signature"]=Hex(((TpmStructureBase)signature).GetTpmRepresentation());
            if(!pubs[0].VerifyQuote(TpmAlgId.Sha256,selection,digests,nonce,quote,signature,null))
                throw new Exception("Quote verification failed");
            report["quote_verified"]=true;
            stage="certify_voting_key";
            var certify=tpm[new AuthValue(auth[1]),new AuthValue(auth[0])].Certify(handles[1],handles[0],nonce,new SchemeEcdsa(TpmAlgId.Sha256),out signature);
            report["certify"]=Hex(certify.GetTpmRepresentation());
            report["certify_signature"]=Hex(((TpmStructureBase)signature).GetTpmRepresentation());
            if(!pubs[0].VerifySignatureOverData(certify.GetTpmRepresentation(),signature))
                throw new Exception("Certify signature verification failed");
            report["certify_signature_verified"]=true;
            stage="read_endorsement_public_and_match_certificate";
            var ekHandle=new TpmHandle(0x81010001u);
            var ek=tpm.ReadPublic(ekHandle,out name,out qualified);
            var inventory=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(
                File.ReadAllText(Path.Combine(Path.GetDirectoryName(args[0]),"node-a-tpm-inventory.json")));
            var certs=(System.Collections.ArrayList)inventory["manufacturer_certificates"];
            var entry=(Dictionary<string,object>)certs[0];
            var cert=new X509Certificate2(Convert.FromBase64String((string)entry["public_certificate_der_base64"]));
            var rsa=(RSA)cert.PublicKey.Key;
            var rsaPublic=rsa.ExportParameters(false);
            if(!rsaPublic.Modulus.SequenceEqual(((Tpm2bPublicKeyRsa)ek.unique).buffer))
                throw new Exception("EK certificate does not match TPM public modulus");
            report["ek_certificate_modulus_matches"]=true;
            report["ek_public"]=Hex(ek.GetTpmRepresentation());
            stage="obtain_windows_endorsement_authorization";
            // Windows supplies this internally or refuses access. Never guess a
            // password, alter authorization, or print/persist the returned value.
            var endorsementAuth=device.GetEndorsementAuth(); secrets.Add(endorsementAuth);
            var credential=Random(32); secrets.Add(credential);
            byte[] encryptedSecret;
            var blob=ek.CreateActivationCredentials(credential,pubs[0].GetName(),out encryptedSecret);
            stage="endorsement_policy_session";
            var policy=tpm.StartAuthSessionEx(TpmSe.Policy,TpmAlgId.Sha256,32);
            handles.Add(policy.Handle);
            TkAuth policyTicket;
            tpm[new AuthValue(endorsementAuth)].PolicySecret(new TpmHandle(TpmRh.Endorsement),policy.Handle,
                new byte[0],new byte[0],new byte[0],0,out policyTicket);
            stage="activate_credential";
            var activated=tpm[new AuthValue(auth[0]),policy].ActivateCredential(handles[0],ekHandle,blob,encryptedSecret);
            secrets.Add(activated);
            if(!activated.SequenceEqual(credential)) throw new Exception("Credential possession mismatch");
            report["activate_credential_verified"]=true;
            report["result"]="TRANSIENT_KEY_QUOTE_PROBE_PASS";
            report["remaining"]=new[]{"EK trust policy", "independent transcript verification", "supervised platform and measured boot validation", "durable production voting key"};
        } catch(Exception ex) {
            report["result"]="INCOMPLETE"; report["stage"]=stage;
            // Error type/message only. No authorization bytes or object dump.
            report["error"]=ex.GetType().Name+": "+ex.Message;
        } finally {
            bool flushed=true;
            if(tpm!=null) for(int i=handles.Count-1;i>=0;i--) {
                try { tpm.FlushContext(handles[i]); } catch {flushed=false;}
            }
            report["own_transients_flushed"]=flushed;
            foreach(var secret in secrets) Array.Clear(secret,0,secret.Length);
            device.Dispose();
        }
        File.WriteAllText(args[0],new JavaScriptSerializer().Serialize(report));
        Console.WriteLine("{0}; attestation_qualified=false; report={1}",report["result"],args[0]);
        return (string)report["result"]=="TRANSIENT_KEY_QUOTE_PROBE_PASS" ? 0 : 1;
    }
}

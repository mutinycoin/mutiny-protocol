//! Finite P256/P384 public receipt verifier. Origin is separate from physical truth.
use super::*;
use p256::ecdsa::signature::Verifier;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Algorithm {P256,P384}
impl Algorithm {fn parse(v:&Value)->Result<Self>{match text(v)? {
    "p256-sha256-v1"=>Ok(Self::P256),"p384-sha384-v1"=>Ok(Self::P384),_=>Err(Error::MissingIssuer)}}}
pub(super) struct Issuer {pin:Hash,subject:Hash,producer:Hash,algorithm:Algorithm,key:Vec<u8>}
impl Issuer {
    pub(super) fn pin(&self)->Hash{self.pin}
    /// Accepted selection supplies the exact pin and applicable subject/producer;
    /// a self-selected key in a receipt cannot enter this list.
    pub(super) fn parse_selected(raw:&[u8],expected:Hash,subject:Hash,producer:Hash)->Result<Self> {
        if hash(raw)!=expected{return Err(Error::Digest);}let v=parse(raw)?;
        let m=exact(&v,&["format","subject_sha256","producer_execution_sha256","algorithm","sec1_public_key_hex"])?;
        if text(&m["format"])?!="b8-clock-public-issuer-v1" || digest(&m["subject_sha256"])?!=subject
            || digest(&m["producer_execution_sha256"])?!=producer{return Err(Error::Scope);}
        let algorithm=Algorithm::parse(&m["algorithm"])?;
        let key=bytes(&m["sec1_public_key_hex"],97)?;
        match algorithm {
            Algorithm::P256=>{
                let k=p256::ecdsa::VerifyingKey::from_sec1_bytes(&key).map_err(|_|Error::MissingIssuer)?;
                if k.to_encoded_point(key.len()==33).as_bytes()!=key{return Err(Error::Canonical);}
            }
            Algorithm::P384=>{
                let k=p384::ecdsa::VerifyingKey::from_sec1_bytes(&key).map_err(|_|Error::MissingIssuer)?;
                if k.to_encoded_point(key.len()==49).as_bytes()!=key{return Err(Error::Canonical);}
            }
        }Ok(Self{pin:expected,subject,producer,algorithm,key})
    }
    fn verify(&self,receipt:&Value,domain:&[u8])->Result<()> {
        if digest(&receipt["subject_sha256"])?!=self.subject || digest(&receipt["issuer_sha256"])?!=self.pin
            || digest(&receipt["producer_execution_sha256"])?!=self.producer
            || Algorithm::parse(&receipt["algorithm"])?!=self.algorithm{return Err(Error::Scope);}
        let limit=match self.algorithm{Algorithm::P256=>72,Algorithm::P384=>104};
        let signature=bytes(&receipt["signature_der_hex"],limit)?;
        if signature.is_empty(){return Err(Error::Signature);}
        let mut projected=receipt.clone();projected.as_object_mut().ok_or(Error::Encoding)?.remove("signature_der_hex");
        let canonical=canonical(&projected)?;let size=domain.len().checked_add(canonical.len()).ok_or(Error::Bound)?;
        let mut message=Vec::with_capacity(size);message.extend_from_slice(domain);message.extend_from_slice(&canonical);
        match self.algorithm {
            Algorithm::P256=>{
                let s=p256::ecdsa::Signature::from_der(&signature).map_err(|_|Error::Signature)?;
                if s.to_der().as_bytes()!=signature{return Err(Error::Canonical);}
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key).map_err(|_|Error::MissingIssuer)?
                    .verify(&message,&s).map_err(|_|Error::Signature)
            }
            Algorithm::P384=>{
                let s=p384::ecdsa::Signature::from_der(&signature).map_err(|_|Error::Signature)?;
                if s.to_der().as_bytes()!=signature{return Err(Error::Canonical);}
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.key).map_err(|_|Error::MissingIssuer)?
                    .verify(&message,&s).map_err(|_|Error::Signature)
            }
        }
    }
}
fn issuer<'a>(s:&'a SelectedMethods,pin:Hash)->Result<&'a Issuer> {
    s.issuers.iter().find(|i|i.pin==pin).ok_or(Error::MissingIssuer)
}
pub(super) fn trace_receipt(s:&SelectedMethods,index:&trace::Index,method:&trace::Method,
    held:&RetainedArtifacts)->Result<()> {
    let v=held.object(&index.receipt)?;
    let m=exact(&v,&["format","subject_sha256","method_sha256","environment_sha256","trace_root_sha256",
        "producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
    if text(&m["format"])?!="b8-clock-producer-receipt-v1" || digest(&m["subject_sha256"])?!=s.subject
        || digest(&m["method_sha256"])?!=method.pin || digest(&m["environment_sha256"])?!=method.environment
        || digest(&m["trace_root_sha256"])?!=index.root || digest(&m["producer_execution_sha256"])?!=s.producer {return Err(Error::Scope);}
    issuer(s,digest(&m["issuer_sha256"])?)?.verify(&v,b"BUILD8-NATIVE-CLOCK-MEASUREMENT-RECEIPT-V1")
}
pub(super) fn event_receipt(s:&SelectedMethods,event:&trace::Event,pin:Hash,index:&trace::Index,
    method:&trace::Method,held:&RetainedArtifacts)->Result<()> {
    if pin==index.pin || pin==index.root || pin==index.receipt{return Err(Error::ReferenceCycle);}
    let v=held.object(&pin)?;
    let m=exact(&v,&["format","subject_sha256","method_sha256","environment_sha256","experiment_id",
        "event_projection_sha256","producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
    if text(&m["format"])?!="b8-clock-event-receipt-v1" || digest(&m["subject_sha256"])?!=s.subject
        || digest(&m["method_sha256"])?!=method.pin || digest(&m["environment_sha256"])?!=method.environment
        || digest(&m["experiment_id"])?!=method.experiment || digest(&m["event_projection_sha256"])?!=event.projection
        || digest(&m["producer_execution_sha256"])?!=s.producer{return Err(Error::Scope);}
    // Receipt grammar has no artifact discovery fields. Its only accepted
    // references terminate at independently pinned subject/method/environment,
    // producer and issuer roles. None may alias an enclosing root or itself.
    for name in ["subject_sha256","method_sha256","environment_sha256","experiment_id","producer_execution_sha256","issuer_sha256"] {
        let refpin=digest(&m[name])?;
        if refpin==pin || refpin==index.pin || refpin==index.root || refpin==index.receipt{return Err(Error::ReferenceCycle);}
    }
    issuer(s,digest(&m["issuer_sha256"])?)?.verify(&v,b"BUILD8-NATIVE-CLOCK-MEASUREMENT-EVENT-RECEIPT-V1")
}
/// A calibrated interval statement with exact selected competence/scope pins.
/// Confidence probabilities are authenticated method inputs, not guessed noise.
pub(super) struct Instrument {pub(super) pin:Hash,pub(super) failure_probability:math::Ratio,
    pub(super) instrument:Hash,pub(super) calibration:Hash,pub(super) environment:Hash,
    pub(super) lower_ns:u64,pub(super) upper_ns:u64,pub(super) coverage_event:Hash}
impl Instrument {
    pub(super) fn parse_selected(raw:&[u8],expected:Hash)->Result<Self> {
        if hash(raw)!=expected{return Err(Error::Digest);}let v=parse(raw)?;
        let m=exact(&v,&["format","subject_sha256","instrument_sha256","calibration_sha256","environment_sha256",
            "coverage_event_sha256","failure_probability","lower_posix_ns","upper_posix_ns",
            "producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
        if text(&m["format"])?!="b8-clock-reference-interval-receipt-v1"{return Err(Error::Encoding);}
        let lower=number(&m["lower_posix_ns"])?;let upper=number(&m["upper_posix_ns"])?;
        math::Interval::new(lower,upper)?;
        Ok(Self{pin:expected,failure_probability:ratio(&m["failure_probability"])?,instrument:digest(&m["instrument_sha256"])? ,
            calibration:digest(&m["calibration_sha256"])? ,environment:digest(&m["environment_sha256"])? ,
            lower_ns:lower,upper_ns:upper,coverage_event:digest(&m["coverage_event_sha256"]) ?})
    }
    pub(super) fn verify(&self,s:&SelectedMethods,held:&RetainedArtifacts,pin:Hash)->Result<()> {
        if pin!=self.pin{return Err(Error::Scope);}let v=held.object(&pin)?;
        if digest(&v["subject_sha256"])?!=s.subject || ratio(&v["failure_probability"])?!=self.failure_probability
            || number(&v["lower_posix_ns"])?!=self.lower_ns || number(&v["upper_posix_ns"])?!=self.upper_ns {return Err(Error::Scope);}
        // Selected opaque instrument inputs bind exact calibration/model and
        // environment artifacts; hashes/signatures alone do not select these.
        for(name,expected)in [("instrument_sha256",self.instrument),("calibration_sha256",self.calibration),
            ("environment_sha256",self.environment),("coverage_event_sha256",self.coverage_event)] {
            if digest(&v[name])?!=expected{return Err(Error::Scope);}held.raw(&expected)?;
        }
        issuer(s,digest(&v["issuer_sha256"])?)?.verify(&v,b"BUILD8-NATIVE-CLOCK-REFERENCE-INTERVAL-V1")
    }
}
pub(super) struct Envelope {pub(super) pin:Hash,pub(super) maximum_error_ppb:u64,
    pub(super) environment_cells:BTreeSet<Hash>,pub(super) instrument:Hash,
    pub(super) calibration:Hash,pub(super) review:Hash,minimum_interval_ns:u64,maximum_interval_ns:u64,
    nonlinearity_ppb:u64}
impl Envelope {
    pub(super) fn parse_selected(raw:&[u8],expected:Hash)->Result<Self> {
        if hash(raw)!=expected{return Err(Error::Digest);}let v=parse(raw)?;
        let m=exact(&v,&["format","subject_sha256","counter_model_sha256","environment_cells","maximum_error_ppb",
            "calibration_provenance_sha256","independent_model_review_sha256","minimum_interval_ns","maximum_interval_ns","counter_nonlinearity_ppb",
            "producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
        if text(&m["format"])?!="b8-clock-class-envelope-receipt-v1"{return Err(Error::Encoding);}
        let a=m["environment_cells"].as_array().ok_or(Error::Encoding)?;
        if a.is_empty() || a.len()>MAX_OBJECTS{return Err(Error::Bound);}
        let mut cells=BTreeSet::new();for c in a{if !cells.insert(digest(c)?){return Err(Error::Scope);}}
        Ok(Self{pin:expected,maximum_error_ppb:number(&m["maximum_error_ppb"])? ,environment_cells:cells,
            instrument:digest(&m["counter_model_sha256"])? ,calibration:digest(&m["calibration_provenance_sha256"])? ,
            review:digest(&m["independent_model_review_sha256"])? ,minimum_interval_ns:number(&m["minimum_interval_ns"])? ,
            maximum_interval_ns:number(&m["maximum_interval_ns"])? ,nonlinearity_ppb:number(&m["counter_nonlinearity_ppb"])?})
    }
    pub(super) fn verify(&self,s:&SelectedMethods,held:&RetainedArtifacts)->Result<()> {
        let v=held.object(&self.pin)?;
        if digest(&v["subject_sha256"])?!=s.subject || number(&v["maximum_error_ppb"])?!=self.maximum_error_ppb
            || digest(&v["counter_model_sha256"])?!=self.instrument{return Err(Error::Scope);}
        held.raw(&self.instrument)?;for c in &self.environment_cells {
            let cell=held.object(c)?;let cell=exact(&cell,&["format","subject_sha256","hardware_sha256","firmware_sha256",
                "os_sha256","execution_environment_sha256","operating_conditions_sha256"])?;
            if text(&cell["format"])?!="b8-clock-supported-environment-cell-v1" || digest(&cell["subject_sha256"])?!=s.subject
                {return Err(Error::Scope);}
            for name in ["hardware_sha256","firmware_sha256","os_sha256","execution_environment_sha256","operating_conditions_sha256"] {
                held.raw(&digest(&cell[name])?)?;
            }
        }
        if self.minimum_interval_ns==0 || self.minimum_interval_ns>s.quantum_ns
            || self.maximum_interval_ns<s.minimum_holdover_ns || self.nonlinearity_ppb>self.maximum_error_ppb {return Err(Error::Coverage);}
        for (pin,format) in [(self.calibration,"b8-clock-class-calibration-provenance-v1"),
            (self.review,"b8-clock-independent-class-review-v1")] {
            let evidence=held.object(&pin)?;let e=exact(&evidence,&["format","subject_sha256","counter_model_sha256",
                "environment_cells","minimum_interval_ns","maximum_interval_ns","maximum_error_ppb","counter_nonlinearity_ppb",
                "producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
            if text(&e["format"])?!=format || digest(&e["subject_sha256"])?!=s.subject
                || digest(&e["counter_model_sha256"])?!=self.instrument || e["environment_cells"]!=v["environment_cells"]
                || number(&e["minimum_interval_ns"])?!=self.minimum_interval_ns
                || number(&e["maximum_interval_ns"])?!=self.maximum_interval_ns
                || number(&e["maximum_error_ppb"])?!=self.maximum_error_ppb
                || number(&e["counter_nonlinearity_ppb"])?!=self.nonlinearity_ppb{return Err(Error::Coverage);}
            issuer(s,digest(&e["issuer_sha256"])?)?.verify(&evidence,b"BUILD8-NATIVE-CLOCK-CLASS-JUSTIFICATION-V1")?;
        }
        // This authenticates the explicitly trusted class model; finite samples
        // never infer a universal class envelope or competence by themselves.
        issuer(s,digest(&v["issuer_sha256"])?)?.verify(&v,b"BUILD8-NATIVE-CLOCK-CLASS-ENVELOPE-V1")
    }
}
/// One signed joint certificate counts once only after its complete finite
/// event scope is reconstructed. Probabilities are authenticated, explicitly
/// justified inputs; signatures do not establish competence or physical truth.
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(super) enum CoverageKind {Reference,Frequency,Capture,Precision,Lifecycle,Authentication,Loss,Leap,Storage,Calibration,Systematic,ClassModel}
impl CoverageKind {
    fn parse(v:&Value)->Result<Self>{match text(v)? {
        "reference"=>Ok(Self::Reference),"frequency"=>Ok(Self::Frequency),"capture"=>Ok(Self::Capture),
        "source-precision"=>Ok(Self::Precision),"lifecycle"=>Ok(Self::Lifecycle),"authentication"=>Ok(Self::Authentication),
        "loss"=>Ok(Self::Loss),"leap"=>Ok(Self::Leap),"storage"=>Ok(Self::Storage),"calibration"=>Ok(Self::Calibration),
        "systematic"=>Ok(Self::Systematic),"class-model"=>Ok(Self::ClassModel),_=>Err(Error::Coverage)}}
    pub(super) fn for_trace(k:trace::Kind)->Self{match k {
        trace::Kind::Precision=>Self::Precision,trace::Kind::Lifecycle=>Self::Lifecycle,
        trace::Kind::Authentication=>Self::Authentication,trace::Kind::Loss=>Self::Loss,
        trace::Kind::Leap=>Self::Leap,trace::Kind::Storage=>Self::Storage}}
}
pub(super) type CoveredEvent=(CoverageKind,Hash);
pub(super) struct CoverageCertificate {pub(super) event:Hash,pub(super) alpha:math::Ratio,pub(super) covered:BTreeSet<CoveredEvent>}
impl CoverageCertificate {
    pub(super) fn verify(s:&SelectedMethods,pin:Hash,held:&RetainedArtifacts)->Result<Self> {
        let v=held.object(&pin)?;let m=exact(&v,&["format","subject_sha256","coverage_event_sha256","failure_probability","covered_events",
            "justification_sha256","producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
        if text(&m["format"])?!="b8-clock-joint-coverage-certificate-v1" || digest(&m["subject_sha256"])?!=s.subject{return Err(Error::Scope);}
        let covered=Self::events(&m["covered_events"])?;
        let event=digest(&m["coverage_event_sha256"])?;held.raw(&event)?;
        // Exact justified bound includes distribution/systematic assumptions.
        // No statistically inferred confidence-in-a-mean substitute is accepted.
        let justification=held.object(&digest(&m["justification_sha256"])?)?;
        let j=exact(&justification,&["format","subject_sha256","failure_probability","covered_events",
            "calibration_provenance_sha256","uncertainty_model_sha256","producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
        if text(&j["format"])?!="b8-clock-uncertainty-bound-justification-v1" || digest(&j["subject_sha256"])?!=s.subject
            || j["failure_probability"]!=m["failure_probability"] || Self::events(&j["covered_events"])?!=covered {return Err(Error::Coverage);}
        let calibration=digest(&j["calibration_provenance_sha256"])?;
        let model=digest(&j["uncertainty_model_sha256"])?;
        if calibration!=s.envelope.calibration && !s.instruments.values().any(|i|i.calibration==calibration)
            {return Err(Error::Coverage);}
        if model!=s.envelope.instrument{return Err(Error::Coverage);}
        held.raw(&calibration)?;held.raw(&model)?;
        issuer(s,digest(&j["issuer_sha256"])?)?.verify(&justification,b"BUILD8-NATIVE-CLOCK-UNCERTAINTY-JUSTIFICATION-V1")?;
        issuer(s,digest(&m["issuer_sha256"])?)?.verify(&v,b"BUILD8-NATIVE-CLOCK-JOINT-COVERAGE-V1")?;
        Ok(Self{event,alpha:ratio(&m["failure_probability"])? ,covered})
    }
    fn events(v:&Value)->Result<BTreeSet<CoveredEvent>> {
        let a=v.as_array().ok_or(Error::Encoding)?;if a.is_empty() || a.len()>MAX_OBJECTS {return Err(Error::Bound);}
        let mut out=BTreeSet::new();for event in a {let e=exact(event,&["kind","commitment_sha256"])?;
            if !out.insert((CoverageKind::parse(&e["kind"])? ,digest(&e["commitment_sha256"])?)){return Err(Error::Coverage);}}
        Ok(out)
    }
}
pub(super) fn external(s:&SelectedMethods,external:&trace::External,held:&RetainedArtifacts)->Result<()> {
    let receipt=s.instruments.get(&external.instrument).ok_or(Error::MissingIssuer)?;
    receipt.verify(s,held,external.instrument)?;
    if external.time.lower!=receipt.lower_ns || external.time.upper!=receipt.upper_ns{return Err(Error::Coverage);}Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    fn sign(mut v:Value,key:&p256::ecdsa::SigningKey,domain:&[u8])->Value {
        let mut message=domain.to_vec();message.extend_from_slice(&canonical(&v).unwrap());
        let signature:p256::ecdsa::Signature=key.sign(&message);
        v["signature_der_hex"]=hex::encode(signature.to_der()).into();v
    }
    #[test] fn modeled_real_p256_receipt_signature_domain_scope_and_tamper() {
        let key=p256::ecdsa::SigningKey::from_bytes((&[9u8;32]).into()).unwrap();
        let subject=[1;32];let producer=[2;32];
        let raw=canonical(&serde_json::json!({"format":"b8-clock-public-issuer-v1",
            "subject_sha256":hex::encode(subject),"producer_execution_sha256":hex::encode(producer),
            "algorithm":"p256-sha256-v1","sec1_public_key_hex":hex::encode(key.verifying_key().to_encoded_point(false))})).unwrap();
        let pin=hash(&raw);let issuer=Issuer::parse_selected(&raw,pin,subject,producer).unwrap();
        let receipt=serde_json::json!({"subject_sha256":hex::encode(subject),"producer_execution_sha256":hex::encode(producer),
            "issuer_sha256":hex::encode(pin),"algorithm":"p256-sha256-v1","committed_measurement":123});
        let signed=sign(receipt,&key,b"MODELED-MEASUREMENT-ONLY");
        assert_eq!(issuer.verify(&signed,b"MODELED-MEASUREMENT-ONLY"),Ok(()));
        assert_eq!(issuer.verify(&signed,b"DIFFERENT-DOMAIN"),Err(Error::Signature));
        let mut bad=signed.clone();bad["committed_measurement"]=124.into();
        assert_eq!(issuer.verify(&bad,b"MODELED-MEASUREMENT-ONLY"),Err(Error::Signature));
        bad=signed;bad["issuer_sha256"]=hex::encode([3;32]).into();
        assert_eq!(issuer.verify(&bad,b"MODELED-MEASUREMENT-ONLY"),Err(Error::Scope));
    }
    #[test] fn modeled_real_p384_receipt_canonical_der_and_exact_key_selection() {
        let key=p384::ecdsa::SigningKey::from_bytes((&[7u8;48]).into()).unwrap();
        let subject=[1;32];let producer=[2;32];
        let raw=canonical(&serde_json::json!({"format":"b8-clock-public-issuer-v1",
            "subject_sha256":hex::encode(subject),"producer_execution_sha256":hex::encode(producer),
            "algorithm":"p384-sha384-v1","sec1_public_key_hex":hex::encode(key.verifying_key().to_encoded_point(false))})).unwrap();
        let pin=hash(&raw);let issuer=Issuer::parse_selected(&raw,pin,subject,producer).unwrap();
        let mut receipt=serde_json::json!({"subject_sha256":hex::encode(subject),"producer_execution_sha256":hex::encode(producer),
            "issuer_sha256":hex::encode(pin),"algorithm":"p384-sha384-v1"});
        let mut message=b"MODELED-P384-ONLY".to_vec();message.extend_from_slice(&canonical(&receipt).unwrap());
        let signature:p384::ecdsa::Signature=key.sign(&message);receipt["signature_der_hex"]=hex::encode(signature.to_der()).into();
        assert_eq!(issuer.verify(&receipt,b"MODELED-P384-ONLY"),Ok(()));
        receipt["signature_der_hex"]=format!("{}00",receipt["signature_der_hex"].as_str().unwrap()).into();
        assert!(issuer.verify(&receipt,b"MODELED-P384-ONLY").is_err());
        assert!(Issuer::parse_selected(&raw,[3;32],subject,producer).is_err());
    }
}

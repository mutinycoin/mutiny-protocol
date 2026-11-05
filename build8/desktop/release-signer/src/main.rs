//! Dedicated offline CLI. No socket, build execution or deployment interface.
const _: () = assert!(
    !mutiny_crypto_v2::WALLET_CUSTODY_ENABLED,
    "Release signer executables must not enable wallet private custody"
);
use mutiny_offline_release_signer::{
    CustodianSession, ReleaseReview, RotationReview, combine_synthetic_descriptors,
    inspect_synthetic_descriptor, verify_synthetic_release, verify_synthetic_rotation,
};
use std::{
    io::{BufRead, IsTerminal, Read},
    path::Path,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, &'static str>;
mod password_input;
#[cfg(test)]
mod recovery_tests;
mod storage_acl;
mod storage_io;
fn read(path: &str, max: u64) -> Result<Vec<u8>> {
    storage_io::read_public(Path::new(path), max)
}
fn write_new(path: &str, bytes: &[u8]) -> Result<()> {
    storage_io::write_new(Path::new(path), bytes)
}
fn read_vault(path: &str) -> Result<Vec<u8>> {
    storage_io::read_vault(Path::new(path))
}
fn password() -> Result<Zeroizing<String>> {
    password_input::prompt("Custodian password (local console only): ")
}
fn approve(required: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err("Approval requires an interactive local terminal");
    }
    println!("To authorize this exact reviewed synthetic object, type: {required}");
    let mut reply = String::new();
    std::io::stdin()
        .lock()
        .take(160)
        .read_line(&mut reply)
        .map_err(|_| "Approval input failed")?;
    if reply.trim() != required {
        return Err("Explicit approval not given");
    }
    Ok(())
}
fn help() {
    println!(
        "Build8 dedicated offline release signer — SYNTHETIC QUALIFICATION ONLY\nProduction key generation and signing remain unavailable.\n\ninit-synthetic A|B|C VAULT PUBLIC_DESCRIPTOR\ndescriptor-synthetic VAULT PUBLIC_DESCRIPTOR\nbackup-synthetic VAULT ENCRYPTED_BACKUP\npolicy-synthetic GENERATION DESCRIPTOR_A DESCRIPTOR_B DESCRIPTOR_C POLICY_OUT\nreview-sign-synthetic VAULT POLICY MANIFEST IMAGE APPROVAL_OUT\nverify-synthetic POLICY MANIFEST APPROVAL_A APPROVAL_B [APPROVAL_C]\nreview-sign-rotation-synthetic VAULT OLD_POLICY NEW_POLICY FINGERPRINT CURRENT|PROPOSED APPROVAL_OUT\nverify-rotation-synthetic OLD_POLICY NEW_POLICY FINGERPRINT CURRENT_A CURRENT_B PROPOSED_A PROPOSED_B\n\nPasswords are read only from the local console, never arguments or environment.\nEvery command drops unlocked keys before exit. No wallet key import. No network, build or deployment command."
    );
}
fn run() -> Result<()> {
    mutiny_crypto_v2::protect_process().map_err(|_| "Process custody protection failed")?;
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() || a == ["--help"] {
        help();
        return Ok(());
    }
    match a[0].as_str() {
        "inspect-descriptor-synthetic" if a.len() == 2 => {
            println!("{}", inspect_synthetic_descriptor(&read(&a[1], 3400)?)?);
        }
        "init-synthetic" if a.len() == 4 => {
            let role = match a[1].as_str() {
                "A" => 1,
                "B" => 2,
                "C" => 3,
                _ => return Err("Custodian role must be A, B or C"),
            };
            if Path::new(&a[2]).exists() || Path::new(&a[3]).exists() {
                return Err("Outputs must not exist");
            }
            let password = password()?;
            let confirmation = password_input::prompt("Repeat local password: ")?;
            if *password != *confirmation {
                return Err("Password confirmation differs");
            }
            drop(confirmation);
            let (vault, descriptor) = CustodianSession::create_synthetic(role, &password)?;
            drop(password);
            write_new(&a[2], &vault)?;
            write_new(&a[3], &descriptor)?;
            println!(
                "Synthetic encrypted vault and PUBLIC descriptor created. Production authority: NO."
            );
        }
        "descriptor-synthetic" if a.len() == 3 => {
            let vault = read_vault(&a[1])?;
            let password = password()?;
            let session = CustodianSession::open_synthetic(&password, &vault)?;
            drop(password);
            let descriptor = session.public_descriptor()?;
            drop(session);
            write_new(&a[2], &descriptor)?;
            println!("PUBLIC synthetic descriptor and dual possession proof exported.");
        }
        "backup-synthetic" if a.len() == 3 => {
            let vault = read_vault(&a[1])?;
            let password = password()?;
            let session = CustodianSession::open_synthetic(&password, &vault)?;
            drop(session);
            drop(password);
            write_new(&a[2], &vault)?;
            if read_vault(&a[2])? != vault {
                return Err("Encrypted backup readback mismatch");
            }
            println!("Encrypted backup verified. No plaintext key export.");
        }
        "policy-synthetic" if a.len() == 6 => {
            let generation = a[1]
                .parse()
                .map_err(|_| "Generation must be a positive integer")?;
            let descriptors = [read(&a[2], 3400)?, read(&a[3], 3400)?, read(&a[4], 3400)?];
            write_new(
                &a[5],
                &combine_synthetic_descriptors(&descriptors, generation)?,
            )?;
            println!("Synthetic policy: all three dual possession proofs verified; threshold 2.");
        }
        "review-sign-synthetic" if a.len() == 6 => {
            let policy = read(&a[2], 5800)?;
            let manifest = read(&a[3], 512)?;
            let image = read(&a[4], 0x1e0000)?;
            let review = ReleaseReview::from_bytes(&policy, &manifest, &image)?;
            println!("{}", review.summary()?);
            approve(&review.confirmation()?)?;
            if read(&a[4], 0x1e0000)? != image {
                return Err("Artifact changed during review");
            }
            let vault = read_vault(&a[1])?;
            let password = password()?;
            let session = CustodianSession::open_synthetic(&password, &vault)?;
            drop(password);
            let approval = session.approve_review(&review)?;
            drop(session);
            write_new(&a[5], &approval)?;
            println!("PUBLIC ReleaseApprovalV1 exported. Synthetic authority only.");
        }
        "verify-synthetic" if (5..=6).contains(&a.len()) => {
            let policy = read(&a[1], 5800)?;
            let manifest = read(&a[2], 512)?;
            let approvals = a[3..]
                .iter()
                .map(|p| read(p, 1600))
                .collect::<Result<Vec<_>>>()?;
            verify_synthetic_release(&policy, &manifest, &approvals)?;
            println!("SYNTHETIC 2-OF-3 DUAL QUORUM PASS");
        }
        "review-sign-rotation-synthetic" if a.len() == 7 => {
            let old = read(&a[2], 5800)?;
            let new = read(&a[3], 5800)?;
            let fingerprint: [u8; 32] = hex::decode(&a[4])
                .map_err(|_| "Fingerprint encoding")?
                .try_into()
                .map_err(|_| "Fingerprint length")?;
            let proposed = match a[5].as_str() {
                "CURRENT" => false,
                "PROPOSED" => true,
                _ => return Err("Choose CURRENT authorization or PROPOSED possession"),
            };
            let review = RotationReview::from_bytes(&old, &new, fingerprint)?;
            println!("{}Approval side: {}", review.summary()?, a[5]);
            approve(&review.confirmation()?)?;
            let vault = read_vault(&a[1])?;
            let password = password()?;
            let session = CustodianSession::open_synthetic(&password, &vault)?;
            drop(password);
            let approval = session.approve_rotation(&review, proposed)?;
            drop(session);
            write_new(&a[6], &approval)?;
            println!("PUBLIC synthetic rotation approval exported.");
        }
        "verify-rotation-synthetic" if a.len() == 8 => {
            let old = read(&a[1], 5800)?;
            let new = read(&a[2], 5800)?;
            let fp: [u8; 32] = hex::decode(&a[3])
                .map_err(|_| "Fingerprint encoding")?
                .try_into()
                .map_err(|_| "Fingerprint length")?;
            let current = [read(&a[4], 1600)?, read(&a[5], 1600)?];
            let proposed = [read(&a[6], 1600)?, read(&a[7], 1600)?];
            verify_synthetic_rotation(&old, &new, fp, &current, &proposed)?;
            println!(
                "SYNTHETIC CURRENT + PROPOSED DUAL QUORUM PASS. Device activation not performed."
            );
        }
        _ => return Err("Unsupported command; production enablement is gated. Use --help."),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Release signer: {e}");
        std::process::exit(1);
    }
}

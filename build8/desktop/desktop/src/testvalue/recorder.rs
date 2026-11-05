//! Append-only mounted-window evidence. Every image is the native viewport framebuffer.
use eframe::egui;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
pub struct Recorder {
    root: PathBuf,
    file: File,
    previous: String,
    pub frame: u64,
    image_sequence: u64,
    source: String,
    source_manifest_sha256: String,
    hwnd: usize,
    title: String,
}
impl Recorder {
    pub fn new(
        root: &Path,
        source: String,
        manifest: &Path,
        hwnd: usize,
        title: String,
    ) -> Result<Self, String> {
        if source.len() != 40 || !source.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Source identity must be a verified full Git commit".into());
        }
        if !root.is_absolute() || root.exists() {
            return Err(
                "Record root must be a new absolute directory; evidence is never overwritten"
                    .into(),
            );
        }
        let metadata = manifest
            .symlink_metadata()
            .map_err(|_| "Explicit source manifest missing")?;
        if !manifest.is_absolute()
            || !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 16 * 1024 * 1024
        {
            return Err("Source manifest must be an absolute bounded plain file".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Source manifest cannot be a reparse point".into());
            }
        }
        let manifest_bytes = std::fs::read(manifest).map_err(|_| "Source manifest read")?;
        let value: serde_json::Value =
            serde_json::from_slice(&manifest_bytes).map_err(|_| "Source manifest JSON")?;
        if value["head"] != source
            || value["files"].as_array().is_none_or(|rows| {
                rows.is_empty()
                    || rows.iter().any(|row| {
                        row["path"].as_str().is_none()
                            || row["sha256"].as_str().is_none_or(|sha| {
                                sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                    })
            })
        {
            return Err(
                "Source manifest must identify this supplied commit and exact file identities"
                    .into(),
            );
        }
        let source_manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(root)
            .map_err(|e| format!("Private record root: {e:?}"))?
        {
            return Err("Record root was not created by this invocation".into());
        }
        std::fs::write(root.join("execution-source-manifest.json"), &manifest_bytes)
            .map_err(|_| "Source manifest preservation")?;
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join("transcript.jsonl"))
            .map_err(|_| "Cannot create evidence transcript")?;
        let exe = std::env::current_exe().map_err(|_| "Cannot identify running test executable")?;
        let exe_hash = hex::encode(Sha256::digest(
            std::fs::read(&exe).map_err(|_| "Cannot hash running executable")?,
        ));
        let summary = serde_json::json!({"classification":"Simulated TEST-VALUE; Windows host; public test keys; NON-SHIPPING; NOT physical; NOT production; NOT a real wallet","source_identity_supplied":source,"execution_source_manifest_sha256":source_manifest_sha256,"source_manifest_file_hashes":"independently verified by launch preflight; supplied manifest is preserved, not a peer authority proof","exe_sha256":exe_hash,"exe":exe,"pid":std::process::id(),"hwnd":hwnd,"title":title,"result":"IN_PROGRESS","node_delivery":"not yet exercised","mounted_flows":"not yet exercised"});
        std::fs::write(
            root.join("summary.json"),
            serde_json::to_vec_pretty(&summary).map_err(|_| "Summary encode")?,
        )
        .map_err(|_| "Summary write")?;
        Ok(Self {
            root: root.to_owned(),
            file,
            previous: "0".repeat(64),
            frame: 0,
            image_sequence: 0,
            source,
            source_manifest_sha256,
            hwnd,
            title,
        })
    }
    pub fn append(
        &mut self,
        banner: bool,
        events: &str,
        state: serde_json::Value,
        screenshot: Option<String>,
    ) -> Result<(), String> {
        if !banner {
            return Err("Permanent TEST-VALUE banner was not drawn".into());
        }
        self.frame = self.frame.checked_add(1).ok_or("Frame overflow")?;
        let utc = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "UTC clock")?
            .as_millis();
        let value = serde_json::json!({"frame":self.frame,"utc_unix_ms":utc,"source_identity_supplied":self.source,"execution_source_manifest_sha256":self.source_manifest_sha256,"pid":std::process::id(),"hwnd":self.hwnd,"title":self.title,"banner_drawn":banner,"input_events":events,"state":state,"screenshot_sha256":screenshot,"previous_sha256":self.previous});
        let mut raw = serde_json::to_vec(&value).map_err(|_| "Transcript encode")?;
        raw.push(b'\n');
        self.file
            .write_all(&raw)
            .and_then(|_| self.file.flush())
            .map_err(|_| "Transcript write")?;
        self.previous = hex::encode(Sha256::digest(&raw));
        Ok(())
    }
    pub fn screenshot(&mut self, image: &egui::ColorImage) -> Result<String, String> {
        let width = u32::try_from(image.size[0]).map_err(|_| "Screenshot width")?;
        let height = u32::try_from(image.size[1]).map_err(|_| "Screenshot height")?;
        if width == 0
            || height == 0
            || image.pixels.len()
                != image.size[0]
                    .checked_mul(image.size[1])
                    .ok_or("Pixel overflow")?
        {
            return Err("Invalid native screenshot".into());
        }
        let pixels = width
            .checked_mul(height)
            .and_then(|n| n.checked_mul(4))
            .ok_or("Screenshot size overflow")?;
        let length = pixels.checked_add(54).ok_or("BMP length overflow")?;
        let mut raw = Vec::with_capacity(length as usize);
        raw.extend_from_slice(b"BM");
        raw.extend_from_slice(&length.to_le_bytes());
        raw.extend_from_slice(&[0; 4]);
        raw.extend_from_slice(&54u32.to_le_bytes());
        raw.extend_from_slice(&40u32.to_le_bytes());
        raw.extend_from_slice(&width.to_le_bytes());
        raw.extend_from_slice(&(-(i32::try_from(height).map_err(|_| "BMP height")?)).to_le_bytes());
        raw.extend_from_slice(&1u16.to_le_bytes());
        raw.extend_from_slice(&32u16.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&pixels.to_le_bytes());
        raw.extend_from_slice(&[0; 16]);
        for pixel in &image.pixels {
            let [r, g, b, _] = pixel.to_array();
            raw.extend_from_slice(&[b, g, r, 255]);
        }
        self.image_sequence = self
            .image_sequence
            .checked_add(1)
            .ok_or("Screenshot sequence overflow")?;
        let path = self.root.join(format!(
            "frame-{:08}-image-{:08}.bmp",
            self.frame, self.image_sequence
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|_| "Evidence screenshot already exists or cannot be created")?;
        file.write_all(&raw)
            .and_then(|_| file.sync_all())
            .map_err(|_| "BMP write")?;
        Ok(hex::encode(Sha256::digest(&raw)))
    }
}

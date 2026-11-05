//! Native translation of the hash-verified Artist tokens and original supplied assets.
//! No operation authority is stored here.
use eframe::egui::{self, Color32, FontFamily, FontId, TextStyle};
/// The active Artist palette accent; logo pixels retain the supplied original red.
pub fn accent(ui: &egui::Ui) -> Color32 {
    ui.visuals().selection.stroke.color
}
pub const RAIL: f32 = 224.0;
pub const CARD_PADDING: i8 = 24;
pub const VERIFIED: Color32 = Color32::from_rgb(0x83, 0xd9, 0xac);
/// One font of the system's own Fonts folder, found through the system Windows directory the OS
/// reports (never a fixed drive letter). `None` falls back to the bundled preview font.
fn system_font(name: &'static str) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::windows::ffi::OsStringExt;
    const MAX_FONT: u64 = 4 * 1024 * 1024;
    let mut buffer = [0u16; 260];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]))
        .join("Fonts")
        .join(name);
    let file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_FONT {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_FONT + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= MAX_FONT as usize
        && bytes.len() >= 4
        && [&b"\0\x01\0\0"[..], &b"OTTO"[..], &b"true"[..]].contains(&&bytes[..4]))
    .then_some(bytes)
}
pub fn install_fonts(ctx: &egui::Context) {
    // Only these two public system fonts are read, once per wallet UI context.
    // Microsoft fonts stay installed on the host; they are never packaged or redistributed.
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Mutiny Sans".into(),
        system_font("segoeui.ttf")
            .map_or_else(
                || egui::FontData::from_static(include_bytes!("../assets/PreviewSans.ttf")),
                egui::FontData::from_owned,
            )
            .into(),
    );
    fonts.font_data.insert(
        "Mutiny Mono".into(),
        system_font("consola.ttf")
            .map_or_else(
                || egui::FontData::from_static(include_bytes!("../assets/PreviewMono.ttf")),
                egui::FontData::from_owned,
            )
            .into(),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "Mutiny Sans".into());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "Mutiny Mono".into());
    ctx.set_fonts(fonts);
}
pub fn logo(ctx: &egui::Context) -> egui::TextureHandle {
    ctx.load_texture(
        "Mutiny original 91acef17",
        egui::ColorImage::from_rgba_unmultiplied(
            [512, 512],
            include_bytes!("../assets/mutiny-logo.rgba"),
        ),
        egui::TextureOptions::LINEAR,
    )
}
pub fn apply(ui: &mut egui::Ui, light: bool) {
    let mut style = (**ui.style()).clone();
    let (canvas, surface, raised, line, text, muted, focus, pending, error, border, accent) =
        if light {
            (
                0xf3f4f5, 0xffffff, 0xeaedf0, 0x7a818a, 0x17191d, 0x515a65, 0x155ac5, 0x785400,
                0xa91d3e, 0x7a818a, 0xc90000,
            )
        } else {
            (
                0x0c0d0f, 0x15171b, 0x1d2025, 0x393e47, 0xf4f4f2, 0xacb1ba, 0x80b8ff, 0xf5cb77,
                0xff9eaa, 0x737b88, 0xff0000,
            )
        };
    let color = |rgb: u32| Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8);
    style.visuals = if light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    style.visuals.override_text_color = Some(color(text));
    style.visuals.weak_text_color = Some(color(muted));
    style.visuals.panel_fill = color(canvas);
    style.visuals.window_fill = color(surface);
    style.visuals.extreme_bg_color = color(surface);
    style.visuals.faint_bg_color = color(raised);
    style.visuals.text_edit_bg_color = Some(color(surface));
    style.visuals.warn_fg_color = color(pending);
    style.visuals.error_fg_color = color(error);
    style.visuals.hyperlink_color = color(focus);
    style.visuals.window_stroke = egui::Stroke::new(1.0, color(line));
    for widget in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.bg_fill = color(surface);
        widget.weak_bg_fill = color(raised);
        widget.bg_stroke = egui::Stroke::new(1.0, color(border));
        widget.fg_stroke = egui::Stroke::new(1.0, color(text));
        widget.corner_radius = 8.into();
    }
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, color(line));
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(3.0, color(focus));
    style.visuals.selection.bg_fill = color(raised);
    style.visuals.selection.stroke = egui::Stroke::new(3.0, color(accent));
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(16.0, 12.0);
    style.spacing.interact_size.y = 44.0;
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(28.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(16.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(14.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(12.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(14.0, FontFamily::Monospace),
    );
    // Branding is confined to selection and the mark; body text retains neutral contrast.
    ui.set_style(style);
}
pub fn card(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style())
        .inner_margin(CARD_PADDING)
        .fill(ui.visuals().window_fill)
        .corner_radius(12)
        .show(ui, content);
}
/// Original 24-unit SVG strokes translated to native painter geometry; source SVGs retained.
pub fn icon(ui: &mut egui::Ui, name: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
    let point = |x: f32, y: f32| rect.min + egui::vec2(x, y) * (20.0 / 24.0);
    let stroke = egui::Stroke::new(1.75 * 20.0 / 24.0, ui.visuals().text_color());
    let segment = |a: (f32, f32), b: (f32, f32)| {
        ui.painter()
            .line_segment([point(a.0, a.1), point(b.0, b.1)], stroke);
    };
    match name {
        "Overview" => {
            for (x, y) in [(3., 3.), (14., 3.), (3., 14.), (14., 14.)] {
                ui.painter().rect_stroke(
                    egui::Rect::from_min_max(point(x, y), point(x + 7., y + 7.)),
                    1.0,
                    stroke,
                    egui::StrokeKind::Middle,
                );
            }
        }
        "Send" => {
            segment((5., 19.), (19., 5.));
            segment((5., 5.), (19., 5.));
            segment((19., 5.), (19., 19.));
        }
        "Receive" => {
            segment((19., 5.), (5., 19.));
            segment((5., 5.), (5., 19.));
            segment((5., 19.), (19., 19.));
        }
        "Activity" => {
            segment((4., 7.), (20., 7.));
            segment((4., 12.), (20., 12.));
            segment((4., 17.), (14., 17.));
        }
        "Management" => {
            for (a, b) in [
                ((12., 3.), (21., 8.)),
                ((21., 8.), (12., 13.)),
                ((12., 13.), (3., 8.)),
                ((3., 8.), (12., 3.)),
                ((3., 12.), (12., 17.)),
                ((12., 17.), (21., 12.)),
                ((3., 16.), (12., 21.)),
                ((12., 21.), (21., 16.)),
            ] {
                segment(a, b);
            }
        }
        "Settings" => {
            segment((4., 7.), (20., 7.));
            segment((4., 17.), (20., 17.));
            ui.painter().circle_stroke(point(8., 7.), 2.5, stroke);
            ui.painter().circle_stroke(point(16., 17.), 2.5, stroke);
        }
        _ => {}
    }
}
pub fn exact(ui: &mut egui::Ui, value: impl Into<String>) {
    ui.add(egui::Label::new(egui::RichText::new(value.into()).monospace()).wrap());
}
pub fn unavailable(ui: &mut egui::Ui, title: &str, dependency: &str) {
    card(ui, |ui| {
        ui.strong(title);
        ui.add(egui::Label::new(dependency).wrap());
    });
}

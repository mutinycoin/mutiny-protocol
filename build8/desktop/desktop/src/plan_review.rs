//! The review screen (phase 7): a THIN egui widget over wallet-core's `Review`.
//!
//! It draws exactly `Review::rows()` under their section headings with each row's emphasis marker,
//! so the text it draws is `Review::render_text()` line for line (pinned by the golden tests below
//! against wallet-core's own golden files). It collects what the person does (the typed destination
//! checks, each acknowledgement the review requires, the confirmation phrase of a high-risk review,
//! Authorize, Cancel) and returns it as `ReviewInput`s for the controller to apply to its
//! `ReviewGate`. It decides nothing itself: the controller's `GateStatus` says what is confirmed and
//! whether `ReviewGate::approve` would succeed at the current verified head, and only then is
//! Authorize enabled. Rendering alone returns no input, so it can never approve. The window is
//! excluded from screen capture (`main.rs`), so the tests check what is drawn, not screenshots.
use eframe::egui;
use mutiny_wallet_core_v8::{
    AckKind, Emphasis, Review, ReviewDigest, Row, Section, Validity, units,
};
use std::collections::BTreeMap;

/// The block countdown of the operation on screen, from the verified head (never the OS clock).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Countdown {
    /// Height of the verified head the status was computed at.
    pub head: u64,
    /// The last block the operation can be included in.
    pub expiry: u64,
    /// The one block the operation is valid in (bond operations, a License sale), if any.
    pub only_block: Option<u64>,
}

impl Countdown {
    pub fn of(validity: &Validity, head: u64) -> Self {
        let only_block = validity
            .valid_only_at
            .or(validity.bound_to_parent.then_some(validity.expiry));
        Self {
            head,
            expiry: validity.expiry,
            only_block,
        }
    }
    /// Blocks after the verified head in which the operation can still be included.
    pub fn blocks_left(&self) -> u64 {
        self.expiry.saturating_sub(self.head)
    }
    pub fn text(&self) -> String {
        let left = self.blocks_left();
        let approx = format!(
            "{}, approximate at the {} s target interval",
            units::approx_blocks(left),
            units::TARGET_BLOCK_SECONDS
        );
        match self.only_block {
            Some(block) => format!(
                "Valid only in block {block}: {left} block(s) left after the verified block {} ({approx}). Any new verified block ends this review.",
                self.head
            ),
            None => format!(
                "Valid until block {}: {left} block(s) left after the verified block {} ({approx}).",
                self.expiry, self.head
            ),
        }
    }
}

/// What the controller reports about the review on screen. Computed from its `ReviewGate`, its plan
/// and the current verified head; never by the widget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateStatus {
    pub digest: ReviewDigest,
    /// The review is the one for the current verified head.
    pub fresh: bool,
    pub acknowledged: Vec<AckKind>,
    pub destinations_confirmed: Vec<usize>,
    pub phrase_confirmed: bool,
    /// `ReviewGate::is_ready` at the current verified head: approving would succeed now.
    pub ready: bool,
    pub countdown: Countdown,
    /// The last refused input: stable code and text (for example a mistyped address ending).
    pub refusal: Option<(String, String)>,
    /// Something the person must be told (the chain moved, the window closed).
    pub notice: Option<String>,
}

/// A review and its gate status, as the controller hands it to the screen.
#[derive(Clone, Debug)]
pub struct ReviewScreen {
    pub review: Review,
    pub status: GateStatus,
}

/// What the person did on the review screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewInput {
    Acknowledge(AckKind),
    ConfirmDestination { index: usize, typed: String },
    ConfirmPhrase(String),
    Authorize,
    Cancel,
}

/// One drawn line: a section heading or a review row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    Heading(Section),
    Row(Row),
}

/// The lines the widget draws, in order: `Review::rows()` under their section headings.
pub fn lines(review: &Review) -> Vec<Line> {
    let mut out = Vec::new();
    let mut current = None;
    for row in review.rows() {
        if current != Some(row.section) {
            out.push(Line::Heading(row.section));
            current = Some(row.section);
        }
        out.push(Line::Row(row));
    }
    out
}

fn marker(emphasis: Emphasis) -> &'static str {
    match emphasis {
        Emphasis::Normal => "  ",
        Emphasis::Important => "* ",
        Emphasis::Warning => "! ",
        Emphasis::Irreversible => "# ",
    }
}

fn heading_text(section: Section) -> String {
    format!("== {} ==", section.title())
}

fn label_text(row: &Row) -> String {
    format!("{}{}", marker(row.emphasis), row.label)
}

/// The text the widget draws, one line per drawn line, in the layout of `Review::render_text()`
/// (a test pins that the two are identical).
pub fn display_text(review: &Review) -> String {
    let mut text = String::new();
    for (index, line) in lines(review).into_iter().enumerate() {
        match line {
            Line::Heading(section) => {
                if index > 0 {
                    text.push('\n');
                }
                text.push_str(&heading_text(section));
                text.push('\n');
            }
            Line::Row(row) => {
                text.push_str(&format!("{}: {}\n", label_text(&row), row.value));
            }
        }
    }
    text
}

fn styled(ui: &egui::Ui, text: String, emphasis: Emphasis) -> egui::RichText {
    let rich = egui::RichText::new(text);
    match emphasis {
        Emphasis::Normal => rich,
        Emphasis::Important => rich.strong(),
        Emphasis::Warning => rich.color(ui.visuals().warn_fg_color),
        Emphasis::Irreversible => rich.strong().color(ui.visuals().error_fg_color),
    }
}

/// What a test clicks or types into.
#[cfg(any(test, feature = "testvalue-window"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Destination(usize),
    Ack(AckKind),
    Phrase,
    Authorize,
    Cancel,
}

/// The review widget. Holds only the text being typed; everything else comes from the screen.
#[derive(Default)]
pub struct ReviewPanel {
    digest: Option<ReviewDigest>,
    typed: BTreeMap<usize, String>,
    phrase: String,
    #[cfg(any(test, feature = "testvalue-window"))]
    pub(crate) targets: Vec<(Target, egui::Rect)>,
    #[cfg(any(test, feature = "testvalue-window"))]
    pub(crate) authorize_enabled: bool,
}

impl ReviewPanel {
    /// Draw `screen` and return what the person did in this frame (nothing, if they did nothing).
    pub fn show(&mut self, ui: &mut egui::Ui, screen: &ReviewScreen) -> Vec<ReviewInput> {
        let review = &screen.review;
        let status = &screen.status;
        if self.digest != Some(status.digest) || !status.fresh {
            // Another review: nothing typed for an earlier one carries over.
            self.typed.clear();
            self.phrase.clear();
            self.digest = Some(status.digest);
        }
        #[cfg(any(test, feature = "testvalue-window"))]
        self.targets.clear();
        let mut inputs = Vec::new();
        ui.heading(review.title());
        // Group contiguous core sections dynamically: future rows are never filtered.
        // The golden plain-text serialization stays unchanged; only native presentation changes.
        let stacked = ui.available_width() <= 760.0;
        let mut lines = lines(review).into_iter().peekable();
        while let Some(line) = lines.next() {
            let Line::Heading(section) = line else {
                continue;
            };
            let mut rows = Vec::new();
            while matches!(lines.peek(), Some(Line::Row(_))) {
                if let Some(Line::Row(row)) = lines.next() {
                    rows.push(row);
                }
            }
            egui::Frame::group(ui.style())
                .fill(ui.visuals().window_fill)
                .corner_radius(12)
                .inner_margin(24)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(section.title()).strong().size(18.0));
                    ui.add_space(8.0);
                    for (index, row) in rows.into_iter().enumerate() {
                        if index > 0 {
                            ui.separator();
                        }
                        ui.add_space(6.0);
                        let label = styled(ui, label_text(&row), row.emphasis);
                        let value = egui::RichText::new(row.value).monospace();
                        if stacked {
                            ui.add(egui::Label::new(label).wrap());
                            ui.add(egui::Label::new(value).wrap());
                        } else {
                            ui.horizontal_top(|ui| {
                                ui.allocate_ui_with_layout(
                                    egui::vec2(180.0, 0.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.add(egui::Label::new(label).wrap());
                                    },
                                );
                                ui.add_space(20.0);
                                ui.add(egui::Label::new(value).wrap());
                            });
                        }
                        ui.add_space(6.0);
                    }
                });
            ui.add_space(12.0);
        }
        let can_authorize = status.fresh && status.ready;
        let gate = egui::Frame::group(ui.style())
            .fill(ui.visuals().window_fill)
            .corner_radius(12)
            .inner_margin(24)
            .show(ui, |ui| {
        ui.label(egui::RichText::new("Review and authorize").strong().size(20.0));
        if let Some(notice) = &status.notice {
            ui.colored_label(ui.visuals().warn_fg_color, notice);
        }
        if !status.fresh {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                "This review is not for the current verified block: nothing can be authorized from it.",
            );
        }
        ui.label(status.countdown.text());
        if let Some((code, message)) = &status.refusal {
            ui.colored_label(ui.visuals().error_fg_color, format!("{message} ({code})"));
        }
        let checks = review.destinations_needing_check();
        for &index in &checks {
            let destination = &review.destinations()[index];
            let done = status.destinations_confirmed.contains(&index);
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "Type the last 8 characters of {}:",
                    mutiny_wallet_core_v8::address_format::encode(
                        &destination.address,
                        review.chain().class
                    )
                ));
                let typed = self.typed.entry(index).or_default();
                let response = ui.add_enabled(
                    status.fresh && !done,
                    egui::TextEdit::singleline(typed)
                        .char_limit(8)
                        .desired_width(96.0),
                );
                #[cfg(any(test, feature = "testvalue-window"))]
                self.targets
                    .push((Target::Destination(index), response.rect));
                if response.changed() && typed.trim().len() == 8 {
                    inputs.push(ReviewInput::ConfirmDestination {
                        index,
                        typed: typed.clone(),
                    });
                }
                if done {
                    ui.label("confirmed");
                }
            });
        }
        let checks_done = checks
            .iter()
            .all(|index| status.destinations_confirmed.contains(index));
        for ack in review.acknowledgements() {
            let given = status.acknowledged.contains(ack);
            let mut ticked = given;
            let enabled = status.fresh && !given && (*ack != AckKind::Destination || checks_done);
            let response =
                ui.add_enabled(enabled, egui::Checkbox::new(&mut ticked, ack.statement()));
            #[cfg(any(test, feature = "testvalue-window"))]
            self.targets.push((Target::Ack(*ack), response.rect));
            if ticked && !given && response.changed() {
                inputs.push(ReviewInput::Acknowledge(*ack));
            }
        }
        if let Some(phrase) = review.confirmation_phrase() {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Type to confirm: {phrase}"));
                let response = ui.add_enabled(
                    status.fresh && !status.phrase_confirmed,
                    egui::TextEdit::singleline(&mut self.phrase).desired_width(200.0),
                );
                #[cfg(any(test, feature = "testvalue-window"))]
                self.targets.push((Target::Phrase, response.rect));
                let typed = self.phrase.split_whitespace().collect::<Vec<_>>().join(" ");
                if response.changed() && typed.len() == phrase.len() {
                    inputs.push(ReviewInput::ConfirmPhrase(self.phrase.clone()));
                }
            });
        }

        ui.horizontal(|ui| {
            let cancel = ui.button("Cancel");
            #[cfg(any(test, feature = "testvalue-window"))]
            self.targets.push((Target::Cancel, cancel.rect));
            if cancel.clicked() {
                inputs.push(ReviewInput::Cancel);
            }
            let button = if can_authorize {
                egui::Button::new(
                    egui::RichText::new("Authorize")
                        .color(egui::Color32::from_rgb(23, 25, 29)),
                ).fill(egui::Color32::from_rgb(244, 244, 242))
            } else {
                egui::Button::new("Authorize")
            };
            let authorize = ui.add_enabled(can_authorize, button);
            #[cfg(any(test, feature = "testvalue-window"))]
            self.targets.push((Target::Authorize, authorize.rect));
            if authorize.clicked() {
                inputs.push(ReviewInput::Authorize);
            }
        });
        });
        let top = gate.response.rect;
        ui.painter().line_segment(
            [top.left_top(), top.right_top()],
            egui::Stroke::new(3.0, ui.visuals().selection.stroke.color),
        );
        // Let a vertical scroll viewport expose the complete last control.
        ui.add_space(12.0);
        #[cfg(any(test, feature = "testvalue-window"))]
        {
            self.authorize_enabled = can_authorize;
        }
        inputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::{
            BondWorld,
            synthetic::{World, address, identity, key_a, key_b},
        },
        wallet_controller_v2::ActivePlan,
    };
    use egui::{Event, Modifiers, PointerButton, Pos2, Rect, vec2};
    use mutiny_wallet_core_v8::{
        BondCreateRequest, KeySigner, OperationRequest, PaymentRequest, PlanPhase, Refusal, plan,
        review,
    };

    /// Drives the real widget headless (`egui::Context::run_ui`, no window) with synthetic
    /// pointer and keyboard events, and applies what it returns to a real `ActivePlan` (wallet-core's
    /// `PlanSession` and `ReviewGate`), exactly as the controller does.
    struct Driver {
        ctx: egui::Context,
        panel: ReviewPanel,
        time: f64,
        width: f32,
        text_bounds: Vec<(String, Rect)>,
    }

    impl Driver {
        fn new() -> Self {
            Self {
                ctx: egui::Context::default(),
                panel: ReviewPanel::default(),
                time: 0.0,
                width: 1600.0,
                text_bounds: Vec::new(),
            }
        }
        /// One frame with `events`; returns the widget's inputs (de-duplicated across the passes
        /// egui may run for one frame) and every text the frame drew, in drawing order.
        fn frame(
            &mut self,
            screen: &ReviewScreen,
            events: Vec<Event>,
        ) -> (Vec<ReviewInput>, Vec<String>) {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(self.width, 6000.0))),
                events,
                time: Some(self.time),
                ..Default::default()
            };
            self.time += 0.25;
            let mut got = Vec::new();
            let panel = &mut self.panel;
            let output = self.ctx.run_ui(input, |ui| {
                for input in panel.show(ui, screen) {
                    if !got.contains(&input) {
                        got.push(input);
                    }
                }
            });
            let mut texts = Vec::new();
            self.text_bounds.clear();
            for clipped in &output.shapes {
                collect_text(&clipped.shape, &mut texts);
                collect_bounds(&clipped.shape, &mut self.text_bounds);
            }
            output.drop_without_applying_deltas();
            (got, texts)
        }
        fn rect(&self, target: Target) -> Rect {
            self.panel
                .targets
                .iter()
                .find(|(t, _)| *t == target)
                .unwrap_or_else(|| panic!("no {target:?} on screen"))
                .1
        }
        /// Press and release the primary button over `target` (two frames, as a person does).
        fn click(&mut self, screen: &ReviewScreen, target: Target) -> Vec<ReviewInput> {
            let pos = self.rect(target).center();
            let mut got = self
                .frame(
                    screen,
                    vec![
                        Event::PointerMoved(pos),
                        Event::PointerButton {
                            pos,
                            button: PointerButton::Primary,
                            pressed: true,
                            modifiers: Modifiers::NONE,
                        },
                    ],
                )
                .0;
            got.extend(
                self.frame(
                    screen,
                    vec![Event::PointerButton {
                        pos,
                        button: PointerButton::Primary,
                        pressed: false,
                        modifiers: Modifiers::NONE,
                    }],
                )
                .0,
            );
            got
        }
        /// Focus `target` and type `text`.
        fn type_into(
            &mut self,
            screen: &ReviewScreen,
            target: Target,
            text: &str,
        ) -> Vec<ReviewInput> {
            let mut got = self.click(screen, target);
            got.extend(self.frame(screen, vec![Event::Text(text.into())]).0);
            got
        }
    }

    fn collect_text(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(text) => out.push(text.galley.text().to_string()),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect_text(s, out)),
            _ => {}
        }
    }

    fn collect_bounds(shape: &egui::Shape, out: &mut Vec<(String, Rect)>) {
        match shape {
            egui::Shape::Text(text) if !text.galley.text().is_empty() => {
                // Empty Grid spacer labels have no glyph bounds (NaN in egui).
                // Every nonempty review label/value still participates below.
                out.push((text.galley.text().to_owned(), text.visual_bounding_rect()))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect_bounds(shape, out)),
            _ => {}
        }
    }

    #[test]
    fn narrow_review_preserves_every_row_and_control_without_horizontal_clipping() {
        let world = payment_world();
        let view = world.view();
        let mut active = payment_plan(&world);
        active.present(&view).unwrap();
        let screen = active.screen(&view).unwrap();
        for width in [360.0, 1150.0] {
            let mut driver = Driver::new();
            driver.width = width;
            driver.frame(&screen, Vec::new());
            let (inputs, drawn) = driver.frame(&screen, Vec::new());
            assert!(inputs.is_empty());
            for row in screen.review.rows() {
                assert!(
                    drawn.contains(&label_text(&row)),
                    "missing label {}",
                    row.label
                );
                assert!(drawn.contains(&row.value), "missing value {}", row.label);
            }
            for (text, rect) in &driver.text_bounds {
                assert!(
                    rect.min.x >= -1.0 && rect.max.x <= width + 1.0,
                    "{width}px viewport clips {text:?} at {rect:?}"
                );
            }
            for (target, rect) in &driver.panel.targets {
                assert!(
                    rect.min.x >= 0.0 && rect.max.x <= width,
                    "{width}px viewport clips {target:?} at {rect:?}"
                );
            }
            assert!(!driver.panel.authorize_enabled);
        }
    }

    /// Key A pays key B 1,000,000 atoms from one 5,000,000-atom coin at head 100: exactly the
    /// scenario of wallet-core's golden `payment_review.txt`.
    fn payment_world() -> World {
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
        world
    }

    fn payment_plan(world: &World) -> ActivePlan {
        let request =
            OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 1_000_000));
        ActivePlan::new(plan(&request, &world.view(), &identity(&key_a())).unwrap())
    }

    fn apply(active: &mut ActivePlan, inputs: Vec<ReviewInput>) {
        for input in inputs {
            let _ = active.apply(&input);
        }
    }

    #[test]
    fn stale_same_digest_clears_typed_destination_and_phrase_without_input() {
        let world = payment_world();
        let mut active = payment_plan(&world);
        active.present(&world.view()).unwrap();
        let mut screen = active.screen(&world.view()).unwrap();
        let mut panel = ReviewPanel::default();
        panel.digest = Some(screen.status.digest);
        panel.typed.insert(0, "old destination consent".into());
        panel.phrase = "old high-risk consent".into();
        screen.status.fresh = false;
        screen.status.ready = false;
        let ctx = egui::Context::default();
        let output = ctx.run_ui(Default::default(), |ui| {
            assert!(panel.show(ui, &screen).is_empty());
        });
        output.drop_without_applying_deltas();
        // Empty entry slots may be recreated while rendering the disabled checks.
        assert!(panel.typed.values().all(String::is_empty));
        assert!(panel.phrase.is_empty());
        assert!(!panel.authorize_enabled);
    }

    #[test]
    fn rendering_alone_cannot_approve_and_a_disabled_authorize_cannot_be_clicked() {
        let world = payment_world();
        let view = world.view();
        let mut active = payment_plan(&world);
        active.present(&view).unwrap();
        let screen = active.screen(&view).unwrap();
        let mut driver = Driver::new();
        for _ in 0..3 {
            let (inputs, texts) = driver.frame(&screen, Vec::new());
            assert!(inputs.is_empty(), "rendering produced input: {inputs:?}");
            assert!(!texts.is_empty());
        }
        assert!(!screen.status.ready && !driver.panel.authorize_enabled);
        // Clicking the disabled Authorize does nothing.
        assert!(driver.click(&screen, Target::Authorize).is_empty());
        assert_eq!(active.phase(), PlanPhase::Presented);
        assert!(active.screen(&view).unwrap().status.acknowledged.is_empty());
    }

    /// Ported (phase 7) from `payment_review_v2::exact_review_change_head_change_cancel_and_single_
    /// consumption`: a changed review clears what was confirmed, a head change clears it, cancel
    /// clears it, and an approval is single use. Now on wallet-core's gate through the real widget.
    #[test]
    fn every_acknowledgement_is_required_and_the_widget_drives_the_real_gate() {
        let world = payment_world();
        let view = world.view();
        let mut active = payment_plan(&world);
        active.present(&view).unwrap();
        let mut driver = Driver::new();
        let screen = active.screen(&view).unwrap();
        let review = screen.review.clone();
        driver.frame(&screen, Vec::new());
        // The Destination acknowledgement is not even offered before the typed check.
        assert!(
            driver
                .click(&screen, Target::Ack(AckKind::Destination))
                .is_empty()
        );
        // Type the address ending (a wrong one is refused by the gate, the right one accepted).
        let index = review.destinations_needing_check()[0];
        let got = driver.type_into(&screen, Target::Destination(index), "00000000");
        assert_eq!(got.len(), 1);
        apply(&mut active, got);
        let screen = active.screen(&view).unwrap();
        assert_eq!(
            screen.status.refusal.as_ref().unwrap().0,
            "DESTINATION_CHECK_FAILED"
        );
        let mut driver = Driver::new();
        driver.frame(&screen, Vec::new());
        let check = review.destination_check_text(index);
        let got = driver.type_into(&screen, Target::Destination(index), &check);
        assert_eq!(
            got,
            vec![ReviewInput::ConfirmDestination {
                index,
                typed: check.clone()
            }]
        );
        apply(&mut active, got);
        // Tick every acknowledgement but the last one: not ready, Authorize disabled.
        let acks = review.acknowledgements().to_vec();
        for ack in &acks[..acks.len() - 1] {
            let screen = active.screen(&view).unwrap();
            driver.frame(&screen, Vec::new());
            let got = driver.click(&screen, Target::Ack(*ack));
            assert_eq!(got, vec![ReviewInput::Acknowledge(*ack)]);
            apply(&mut active, got);
        }
        let screen = active.screen(&view).unwrap();
        driver.frame(&screen, Vec::new());
        assert!(!screen.status.ready && !driver.panel.authorize_enabled);
        assert!(driver.click(&screen, Target::Authorize).is_empty());
        let key = KeySigner::for_test(key_a()).unwrap();
        assert_eq!(
            active.authorize(&key, &view).unwrap_err(),
            Refusal::AcknowledgementMissing(*acks.last().unwrap())
        );
        // The last one: ready, Authorize enabled and clickable.
        let got = driver.click(&screen, Target::Ack(*acks.last().unwrap()));
        apply(&mut active, got);
        let screen = active.screen(&view).unwrap();
        driver.frame(&screen, Vec::new());
        assert!(screen.status.ready && driver.panel.authorize_enabled);
        // Ready is not approved: a frame without input still returns nothing.
        assert!(driver.frame(&screen, Vec::new()).0.is_empty());
        assert_eq!(
            driver.click(&screen, Target::Authorize),
            vec![ReviewInput::Authorize]
        );
        // A head change clears the gate: the review is redone at the new head, nothing confirmed.
        let later = world.advanced();
        let later_view = later.view();
        active.on_head(&later_view);
        let screen = active.screen(&later_view).unwrap();
        assert!(screen.status.acknowledged.is_empty() && !screen.status.ready);
        assert_ne!(screen.status.digest, review.binding());
        driver.frame(&screen, Vec::new());
        assert!(!driver.panel.authorize_enabled);
        // Cancel clears it as well and drops the plan.
        let got = driver.click(&screen, Target::Cancel);
        assert_eq!(got, vec![ReviewInput::Cancel]);
        active.discard().unwrap();
        assert_eq!(active.phase(), PlanPhase::Discarded);
        // Single use: an approval is consumed by its authorization.
        let mut active = payment_plan(&world);
        active.present(&view).unwrap();
        let screen = active.screen(&view).unwrap();
        for index in screen.review.destinations_needing_check() {
            let typed = screen.review.destination_check_text(index);
            active
                .apply(&ReviewInput::ConfirmDestination { index, typed })
                .unwrap();
        }
        for ack in screen.review.acknowledgements() {
            active.apply(&ReviewInput::Acknowledge(*ack)).unwrap();
        }
        active.authorize(&key, &view).unwrap();
        assert_eq!(active.phase(), PlanPhase::Signed);
        assert_eq!(
            active.authorize(&key, &view).unwrap_err(),
            Refusal::NotPresented
        );
    }

    #[test]
    fn newly_enabled_authorize_requires_a_rendered_gate_before_native_click() {
        let world = payment_world();
        let view = world.view();
        let mut active = payment_plan(&world);
        active.present(&view).unwrap();
        let mut driver = Driver::new();
        let screen = active.screen(&view).unwrap();
        driver.frame(&screen, Vec::new());
        for index in screen.review.destinations_needing_check() {
            let typed = screen.review.destination_check_text(index);
            let got = driver.type_into(&screen, Target::Destination(index), &typed);
            apply(&mut active, got);
        }
        for ack in screen.review.acknowledgements() {
            let screen = active.screen(&view).unwrap();
            driver.frame(&screen, Vec::new());
            let got = driver.click(&screen, Target::Ack(*ack));
            assert_eq!(got, vec![ReviewInput::Acknowledge(*ack)]);
            apply(&mut active, got);
        }
        // Controller updates happen after the widget's frame: the gate is ready,
        // but the preceding widget snapshot still has Authorize disabled.
        let screen = active.screen(&view).unwrap();
        assert!(screen.status.ready);
        assert!(!driver.panel.authorize_enabled);
        let click = |pos: Pos2| {
            vec![
                Event::PointerMoved(pos),
                Event::PointerButton {
                    pos,
                    button: PointerButton::Primary,
                    pressed: true,
                    modifiers: Modifiers::NONE,
                },
                Event::PointerButton {
                    pos,
                    button: PointerButton::Primary,
                    pressed: false,
                    modifiers: Modifiers::NONE,
                },
            ]
        };
        let pos = driver.rect(Target::Authorize).center();
        assert!(driver.frame(&screen, click(pos)).0.is_empty());
        assert_eq!(active.phase(), PlanPhase::Presented);
        // An ordinary frame registers the now-enabled widget. The same real
        // raw press/release batch then authorizes; no clock or gate override.
        driver.frame(&screen, Vec::new());
        let pos = driver.rect(Target::Authorize).center();
        assert_eq!(
            driver.frame(&screen, click(pos)).0,
            vec![ReviewInput::Authorize]
        );
        active
            .authorize(&KeySigner::for_test(key_a()).unwrap(), &view)
            .unwrap();
        assert_eq!(active.phase(), PlanPhase::Signed);
    }

    /// Ported (phase 7) from `payment_review_v2::render_without_explicit_input_cannot_approve`.
    #[test]
    fn render_without_explicit_input_cannot_approve() {
        let world = payment_world();
        let view = world.view();
        let mut active = payment_plan(&world);
        active.present(&view).unwrap();
        let screen = active.screen(&view).unwrap();
        let ctx = egui::Context::default();
        let mut panel = ReviewPanel::default();
        let output = ctx.run_ui(Default::default(), |ui| {
            assert!(panel.show(ui, &screen).is_empty());
        });
        assert!(!output.shapes.is_empty());
        output.drop_without_applying_deltas();
        assert!(!panel.authorize_enabled);
        assert!(active.screen(&view).unwrap().status.acknowledged.is_empty());
    }

    /// A high-risk review asks for its typed confirmation phrase: until it is typed the review is
    /// not ready, whatever else is given.
    #[test]
    fn a_high_risk_review_needs_its_confirmation_phrase() {
        let (world, request) = bond_world();
        let view = world.view();
        let mut active = ActivePlan::new(plan(&request, &view, &identity(&key_a())).unwrap());
        active.present(&view).unwrap();
        let screen = active.screen(&view).unwrap();
        let phrase = screen
            .review
            .confirmation_phrase()
            .expect("bond creation is high risk");
        for index in screen.review.destinations_needing_check() {
            let typed = screen.review.destination_check_text(index);
            active
                .apply(&ReviewInput::ConfirmDestination { index, typed })
                .unwrap();
        }
        for ack in screen.review.acknowledgements() {
            active.apply(&ReviewInput::Acknowledge(*ack)).unwrap();
        }
        let screen = active.screen(&view).unwrap();
        assert!(!screen.status.ready);
        let mut driver = Driver::new();
        driver.frame(&screen, Vec::new());
        assert!(!driver.panel.authorize_enabled);
        let got = driver.type_into(&screen, Target::Phrase, &phrase.to_ascii_lowercase());
        assert_eq!(got.len(), 1);
        apply(&mut active, got);
        let screen = active.screen(&view).unwrap();
        assert!(screen.status.phrase_confirmed && screen.status.ready);
        // The native funded-bond window remains finite rather than a one-block draft.
        assert_eq!(screen.status.countdown.only_block, None);
        assert!(
            screen
                .status
                .countdown
                .text()
                .contains("Valid until block 245: 145 block(s) left")
        );
    }

    /// The fixture node's bond world of wallet-core's golden `bond_create_review.txt`: key A bonds
    /// 150 MUT for the node from one 300 MUT coin at head 100 (same values as wallet-core's
    /// `review_completeness_bond.rs`).
    fn bond_world() -> (BondWorld, OperationRequest) {
        let mut world = BondWorld::new(100);
        world.coin(address(&key_a(), 1), 30_000_000_000, 0x31);
        let request = OperationRequest::BondCreate(BondCreateRequest::new(
            world.node(),
            1,
            15_000_000_000,
            [0x42; 32],
        ));
        (world, request)
    }

    const GOLDEN_PAYMENT: &str = include_str!("../../wallet-core/tests/golden/payment_review.txt");
    const GOLDEN_BOND_CREATE: &str =
        include_str!("../../wallet-core/tests/golden/bond_create_review.txt");

    /// The widget's text is wallet-core's `render_text()` line for line, for the payment and the
    /// bond-creation scenarios of wallet-core's own golden files; and the frame really draws every
    /// heading, label and value of it, in order.
    #[test]
    fn golden_payment_and_bond_reviews_are_drawn_exactly_as_wallet_core_renders_them() {
        let world = payment_world();
        let payment = review(
            &plan(
                &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 1_000_000)),
                &world.view(),
                &identity(&key_a()),
            )
            .unwrap(),
            &world.view(),
        )
        .unwrap();
        let (bonds, request) = bond_world();
        let bond = review(
            &plan(&request, &bonds.view(), &identity(&key_a())).unwrap(),
            &bonds.view(),
        )
        .unwrap();
        for (review, golden, name) in [
            (payment, GOLDEN_PAYMENT, "payment_review.txt"),
            (bond, GOLDEN_BOND_CREATE, "bond_create_review.txt"),
        ] {
            let text = display_text(&review);
            assert_eq!(
                text,
                review.render_text(),
                "{name}: widget text != render_text()"
            );
            assert!(
                text == golden,
                "{name}: widget text != wallet-core golden:\n{text}"
            );
            // What the frame draws: every heading, label and value, in this order.
            let screen = ReviewScreen {
                status: GateStatus {
                    digest: review.binding(),
                    fresh: true,
                    acknowledged: Vec::new(),
                    destinations_confirmed: Vec::new(),
                    phrase_confirmed: false,
                    ready: false,
                    countdown: Countdown {
                        head: 100,
                        expiry: 245,
                        only_block: None,
                    },
                    refusal: None,
                    notice: None,
                },
                review: review.clone(),
            };
            let mut driver = Driver::new();
            driver.frame(&screen, Vec::new());
            let (_, drawn) = driver.frame(&screen, Vec::new());
            let mut at = 0;
            for line in lines(&review) {
                let wanted = match line {
                    Line::Heading(section) => vec![section.title().to_owned()],
                    Line::Row(row) => vec![label_text(&row), row.value.clone()],
                };
                for piece in wanted {
                    let found = drawn[at..]
                        .iter()
                        .position(|t| *t == piece)
                        .unwrap_or_else(|| panic!("{name}: not drawn in order: {piece:?}"));
                    at += found + 1;
                }
            }
        }
    }
}

//! Fixed public rehearsal input. It emits egui events into the actual native frame;
//! it owns no controller, request, ReviewInput, signer, key or approval capability.
use eframe::egui;
use std::collections::VecDeque;
#[derive(Clone, Debug)]
pub enum Action {
    Click(String),
    Text { target: String, value: String },
    Wait(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumed_start_button_enqueues_next_click_without_losing_settling_frame() {
        let ctx = egui::Context::default();
        let window = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(600., 400.));
        let mut player = Player::default();
        let mut targets = Vec::new();
        let mut start_clicked = false;
        let mut next_clicked = false;
        for frame in 0..6 {
            if frame == 2 {
                player.queue([Action::Click("host:Start".into())]).unwrap();
            }
            let mut raw = egui::RawInput {
                screen_rect: Some(window),
                time: Some(frame as f64 * 0.1),
                ..Default::default()
            };
            player.inject(&mut raw, &targets, window, window);
            if frame == 3 {
                assert!(
                    raw.events.is_empty(),
                    "queued follow-up skipped settling frame"
                );
            }
            targets.clear();
            let output = ctx.run_ui(raw, |ui| {
                let start = ui.button("Start native sequence");
                targets.push(("host:Start".to_owned(), start.rect));
                if start.clicked() {
                    assert!(!start_clicked);
                    start_clicked = true;
                    assert_eq!(player.idle, 1);
                    player.queue([Action::Click("form:Next".into())]).unwrap();
                    assert_eq!(player.idle, 1, "callback erased settling frame");
                }
                let next = ui.button("Next actual form button");
                targets.push(("form:Next".to_owned(), next.rect));
                if next.clicked() {
                    assert!(start_clicked);
                    assert_eq!(frame, 4);
                    next_clicked = true;
                }
            });
            output.drop_without_applying_deltas();
        }
        assert!(start_clicked && next_clicked);
        assert!(player.done());
        assert!(player.failure.is_none());
    }

    #[test]
    fn actual_reload_then_next_callback_keeps_settling_and_rejects_unconsumed_sequence() {
        let ctx=egui::Context::default();let window=egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(700.,400.));
        let mut player=Player::default();let mut targets=Vec::new();let mut reload=false;let mut next=false;let mut phase=false;
        for frame in 0..9 {
            if frame==2 {player.queue([Action::Click("continuous:Reload script".into())]).unwrap();assert!(!player.sequence_consumed());}
            let mut raw=egui::RawInput{screen_rect:Some(window),time:Some(frame as f64*0.1),..Default::default()};
            player.inject(&mut raw,&targets,window,window);targets.clear();
            let out=ctx.run_ui(raw,|ui|{
                let r=ui.button("Reload script");targets.push(("continuous:Reload script".into(),r.rect));
                if r.clicked(){assert!(player.sequence_consumed());assert!(!player.done());assert_eq!(player.idle,1);reload=true;player.queue([Action::Click("continuous:Next phase".into())]).unwrap();assert_eq!(player.idle,1);}
                let r=ui.button("Next phase");targets.push(("continuous:Next phase".into(),r.rect));
                if r.clicked(){assert!(reload);assert!(player.sequence_consumed());assert!(!player.done());next=true;player.queue([Action::Click("form:Actual phase".into())]).unwrap();assert_eq!(player.idle,1);}
                let r=ui.button("Actual phase");targets.push(("form:Actual phase".into(),r.rect));if r.clicked(){assert!(next);phase=true;}
            });out.drop_without_applying_deltas();
        }
        assert!(reload&&next&&phase);assert!(player.done());assert!(player.failure.is_none());
        player.failure=Some("retained real refusal".into());assert!(!player.sequence_consumed());
        // Actual egui callback-chain primitive only; no Controller, economic
        // authorization, mounted HWND, native delivery or finality inferred.
    }

    #[test]
    fn queued_actions_and_incomplete_text_cannot_be_replaced_by_a_callback() {
        let mut player = Player::default();
        player.queue([Action::Click("host:Start".into())]).unwrap();
        assert!(player.queue([Action::Click("form:Other".into())]).is_err());
        assert_eq!(player.pending.len(), 1);
        let window = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(600., 400.));
        let target = egui::Rect::from_min_size(egui::pos2(20., 20.), egui::vec2(100., 20.));
        let mut text_player = Player::default();
        text_player
            .queue([Action::Text {
                target: "field:Public".into(),
                value: "public fixture".into(),
            }])
            .unwrap();
        text_player.inject(
            &mut egui::RawInput::default(),
            &[("field:Public".into(), target)],
            window,
            window,
        );
        assert!(text_player.text.is_some());
        assert!(
            text_player
                .queue([Action::Click("form:Other".into())])
                .is_err()
        );
        let mut raw = egui::RawInput::default();
        text_player.inject(&mut raw, &[], window, window);
        assert!(
            raw.events
                .iter()
                .any(|event| matches!(event, egui::Event::Text(text) if text == "public fixture"))
        );
        assert_eq!(text_player.idle, 2);
    }
}
#[derive(Default)]
pub struct Player {
    pending: VecDeque<Action>,
    text: Option<String>,
    frames: u32,
    idle: u16,
    pub last: Option<String>,
    pub failure: Option<String>,
}
impl Player {
    pub fn queue(&mut self, actions: impl IntoIterator<Item = Action>) -> Result<(), String> {
        if !self.pending.is_empty() || self.text.is_some() {
            return Err("Previous native input sequence is still active".into());
        }
        self.pending.extend(actions);
        self.frames = 0;
        // A consumed raw Click can invoke an actual button callback in this frame.
        // It may enqueue the next sequence, while the native settling frame remains.
        // Pending actions or incomplete text entry still reject replacement.
        Ok(())
    }
    /// An actual callback may hand off a fully consumed sequence while its
    /// settling frame remains. Pending/text/failure still refuse replacement.
    pub fn sequence_consumed(&self) -> bool {
        self.pending.is_empty() && self.text.is_none() && self.failure.is_none()
    }
    pub fn done(&self) -> bool {
        self.pending.is_empty() && self.text.is_none() && self.idle == 0
    }
    pub fn inject(
        &mut self,
        input: &mut egui::RawInput,
        targets: &[(String, egui::Rect)],
        window: egui::Rect,
        scroll: egui::Rect,
    ) {
        if self.failure.is_some() || self.done() {
            return;
        }
        self.frames += 1;
        if self.frames > 2400 {
            self.failure = Some("Bounded native player exceeded2400 frames".into());
            return;
        }
        let modifiers = egui::Modifiers::NONE;
        if let Some(value) = self.text.take() {
            let command = egui::Modifiers {
                ctrl: true,
                command: true,
                ..Default::default()
            };
            input.events.push(egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: command,
            });
            input.events.push(egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: false,
                repeat: false,
                modifiers: command,
            });
            input.events.push(egui::Event::Text(value));
            self.idle = 2;
            return;
        }
        if self.idle > 0 {
            self.idle -= 1;
            return;
        }
        let Some(action) = self.pending.front().cloned() else {
            return;
        };
        if let Action::Wait(frames) = action {
            self.idle = frames;
            self.pending.pop_front();
            return;
        }
        let key = match &action {
            Action::Click(key) => key,
            Action::Text { target, .. } => target,
            _ => unreachable!(),
        };
        let Some((_, rect)) = targets.iter().find(|(name, _)| name == key) else {
            return;
        };
        let visible = if key.starts_with("host:") {
            window
        } else {
            scroll
        };
        if !visible.is_positive() {
            return;
        }
        if !visible.contains_rect(*rect) {
            // Native ScrollArea handles this event. The player does not modify scroll state.
            let delta = if rect.max.y > visible.max.y {
                -180.
            } else {
                180.
            };
            input
                .events
                .push(egui::Event::PointerMoved(visible.center()));
            input.events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                phase: egui::TouchPhase::Move,
                delta: egui::vec2(0., delta),
                modifiers,
            });
            return;
        }
        let pos = rect.center();
        input.events.push(egui::Event::PointerMoved(pos));
        input.events.push(egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers,
        });
        // One native input batch represents a click without holding the button
        // across expensive real wallet frames. No egui clock/click threshold changes.
        input.events.push(egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers,
        });
        self.last = Some(format!("native click batch {action:?} at {pos:?}"));
        if let Action::Text { value, .. } = action {
            self.text = Some(value);
        }
        self.pending.pop_front();
        // Wallet gates are updated after the widgets have rendered. Give egui
        // one ordinary frame to register a newly enabled control before another click.
        self.idle = 1;
    }
}

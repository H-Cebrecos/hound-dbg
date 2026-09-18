//! Breakpoint panel.
//!
//! Lists every breakpoint set across the loaded objects, grouped by object
//! and ordered by address. Breakpoints themselves live where they are set,
//! in [`ObjectFile::breakpoints`](crate::ObjectFile) — this panel is a view
//! over that set, not a second copy of it.
//!
//! Each row resolves its address back through the object's disassembly to
//! the containing function, so a breakpoint reads as `function+0x1c` rather
//! than a bare address. Clicking a row reveals it in the disassembly panel;
//! clicking its dot clears it, mirroring the gutter in the disassembly view.

use egui::{Context, RichText};

use crate::{Location, ObjectKey};

/// Render the breakpoint panel.
pub fn break_panel(ctx: &Context, ui_app: &mut super::Ui) {
    egui::SidePanel::left("breakpoints")
        .show_separator_line(true)
        .resizable(true)
        .default_width(320.0)
        .show_animated(ctx, ui_app.break_panel_open, |ui| {
            // Applied after the walk below, which borrows the objects.
            let mut remove: Option<(ObjectKey, u64)> = None;
            let mut reveal: Option<(ObjectKey, u64)> = None;
            let mut clear_all = false;

            let total: usize = ui_app
                .app
                .objects
                .iter()
                .map(|o| o.1.breakpoints.len())
                .sum();

            // ---------- Header ----------
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(RichText::new("Breakpoints").heading());
                ui.label(RichText::new(total.to_string()).weak());

                if total > 0 {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new("Clear all").weak()).frame(false))
                            .on_hover_text("Remove every breakpoint")
                            .clicked()
                        {
                            clear_all = true;
                        }
                    });
                }
            });

            ui.separator();

            if total == 0 {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("No breakpoints set")
                        .italics()
                        .weak()
                        .color(super::THEME.overlay1),
                );
                ui.label(
                    RichText::new("Click the gutter left of an instruction to set one.")
                        .italics()
                        .weak()
                        .color(super::THEME.overlay0),
                );
                return;
            }

            let row_height = ui.text_style_height(&egui::TextStyle::Monospace);

            egui::ScrollArea::vertical()
                .id_salt("break_scroll")
                .show(ui, |ui| {
                    for (key, obj) in ui_app.app.objects.iter() {
                        if obj.breakpoints.is_empty() {
                            continue;
                        }

                        // ---------- Per-object group ----------
                        let id = ui.make_persistent_id(("breakpoints", &obj.name));
                        egui::collapsing_header::CollapsingState::load_with_default_open(
                            ui.ctx(),
                            id,
                            true,
                        )
                        .show_header(ui, |ui| {
                            ui.label(RichText::new(&obj.name).strong());
                            ui.label(RichText::new(obj.breakpoints.len().to_string()).weak());
                        })
                        .body(|ui| {
                            let mut addrs: Vec<u64> = obj.breakpoints.iter().copied().collect();
                            addrs.sort_unstable();

                            for addr in addrs {
                                let func = obj.disasm.function_containing(addr);
                                let selected = ui_app.app.active
                                    == func.map(|f| Location {
                                        obj: key,
                                        addr: f.addr,
                                    });

                                let row = ui
                                    .horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;

                                        // Same affordance as the disassembly
                                        // gutter: the dot is the toggle.
                                        let (dot_rect, dot) = ui.allocate_exact_size(
                                            egui::vec2(14.0, row_height),
                                            egui::Sense::click(),
                                        );
                                        let color = if dot.hovered() {
                                            super::THEME.red.gamma_multiply(0.6)
                                        } else {
                                            super::THEME.red
                                        };
                                        ui.painter().circle_filled(dot_rect.center(), 4.0, color);

                                        if dot.on_hover_text("Remove breakpoint").clicked() {
                                            remove = Some((key, addr));
                                        }

                                        let mut location = RichText::new(match func {
                                            Some(f) if f.addr == addr => f.name.to_owned(),
                                            Some(f) => format!("{}+{:#x}", f.name, addr - f.addr),
                                            None => "<no symbol>".to_owned(),
                                        });
                                        if selected {
                                            location = location.color(super::THEME.mauve);
                                        } else if func.is_none() {
                                            location = location.italics().weak();
                                        }

                                        let label = ui.selectable_label(
                                            selected,
                                            RichText::new(format!("{addr:08x}")).weak().monospace(),
                                        );
                                        ui.label(location);

                                        label
                                    })
                                    .inner;

                                if row.clicked() {
                                    reveal = Some((key, addr));
                                }

                                row.context_menu(|ui| {
                                    if ui.button("Copy address").clicked() {
                                        ui.ctx().copy_text(format!("{addr:x}"));
                                        ui.close();
                                    }

                                    if let Some(f) = func
                                        && ui.button("Copy location").clicked()
                                    {
                                        ui.ctx().copy_text(format!(
                                            "{}+{:#x}",
                                            f.name,
                                            addr - f.addr
                                        ));
                                        ui.close();
                                    }

                                    if ui.button("Remove breakpoint").clicked() {
                                        remove = Some((key, addr));
                                        ui.close();
                                    }
                                });
                            }
                        });
                    }
                });

            // ---------- Deferred mutations ----------
            if clear_all {
                for obj in &mut ui_app.app.objects {
                    obj.1.breakpoints.clear();
                }
            }

            if let Some((obj_idx, addr)) = remove
                && let Some(obj) = ui_app.app.objects.get_mut(obj_idx)
            {
                obj.breakpoints.remove(&addr);
            }

            if let Some((obj_idx, addr)) = reveal {
                ui_app.reveal(obj_idx, addr);
            }
        });
}

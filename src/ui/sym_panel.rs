use egui::{Color32, Context, RichText};

use crate::truncate_middle;

pub fn sym_panel(ctx: &Context, ui_app: &mut super::Ui) {
    egui::SidePanel::left("sym_panel")
        .show_separator_line(false)
        .resizable(true)
        .default_width(400.0)
        .show_animated(ctx, ui_app.symbol_panel_open, |ui| {
            // ---------- Header ----------
            ui.add(
                egui::TextEdit::singleline(&mut ui_app.symbol_filter)
                    .hint_text("Search symbols...")
                    .desired_width(f32::INFINITY),
            );

            // ---------- Footer ----------
            let footer_height = 32.0;

            let mut body_rect = ui.available_rect_before_wrap();
            body_rect.max.y -= footer_height;

            let mut footer_rect = ui.available_rect_before_wrap();
            footer_rect.min.y = footer_rect.max.y - footer_height;
            ui.scope_builder(egui::UiBuilder::new().max_rect(body_rect), |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    let filter = ui_app.symbol_filter.trim().to_ascii_lowercase();

                    for (file_idx, file) in &mut ui_app.app.objects.iter().enumerate() {
                        let matching: Vec<_> = file
                            .disasm
                            .functions()
                            .filter(|sym| {
                                filter.is_empty() || sym.name.to_ascii_lowercase().contains(&filter)
                            })
                            .collect();

                        if matching.is_empty() {
                            continue;
                        }

                        let id = if filter.is_empty() {
                            ui.make_persistent_id(("file", &file.name))
                        } else {
                            ui.make_persistent_id(("search", &file.name))
                        };

                        let mut file_text = RichText::new(&file.name).heading();
                        if let Some(active) = ui_app.app.active_file
                            && active == file_idx
                        {
                            file_text = file_text.color(super::THEME.sky);
                        }
                        egui::CollapsingHeader::new(file_text)
                            .id_salt(id)
                            .default_open(!filter.is_empty())
                            .show(ui, |ui| {
                                for sym in matching {
                                    let mut text = RichText::new(truncate_middle(
                                        &sym.name,
                                        (ui.available_width() / 8.) as usize,
                                    ))
                                    .weak();

                                    if let Some(active_id) = ui_app.app.active_sym
                                        && active_id == sym.addr
                                    {
                                        if let Some(active) = ui_app.app.active_file
                                            && active == file_idx
                                        {
                                            text = text.strong().color(super::THEME.sky);
                                        }
                                    }

                                    let response = ui
                                        .selectable_label(false, text)
                                        //this instead of on_hover_text to prevent very long symbol names from wrapping as well as for multi-color
                                        .on_hover_ui(|ui| {
                                            ui.set_max_width(f32::MAX);

                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    RichText::new(format!("0x{:x}:", sym.addr))
                                                        .weak()
                                                        .monospace(),
                                                );

                                                ui.label(sym.name);
                                            });
                                        });

                                    response.context_menu(|ui| {
                                        if ui.button("Copy symbol name").clicked() {
                                            ui.ctx().copy_text(sym.name.to_owned());
                                        }

                                        if ui.button("Copy symbol address").clicked() {
                                            ui.ctx().copy_text(format!("{:x}", sym.addr));
                                        }

                                        //TODO: show greyed out if no trace is loaded
                                        if ui
                                            .button(
                                                RichText::new("Find instances in trace")
                                                    .color(Color32::DEBUG_COLOR),
                                            )
                                            .clicked()
                                        {
                                            //TODO
                                        }
                                        //...
                                    });
                                    if response.clicked() {
                                        ui_app.app.active_sym = Some(sym.addr);
                                        ui_app.app.active_file = Some(file_idx); //TODO
                                    }
                                }
                            });
                    }
                });
            });

            ui.scope_builder(egui::UiBuilder::new().max_rect(footer_rect), |ui| {
                ui.separator();

                if !ui_app.app.objects.is_empty() {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("+ Add additional object")
                                    .italics()
                                    .weak(),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new()
                            // .add_filter("Supported", &["elf"])
                            .pick_file()
                        {
                            ui_app.open_file(&path)
                        }
                    }
                } else {
                    ui.label(
                        egui::RichText::new("No object files loaded")
                            .italics()
                            .weak(),
                    );
                }
            });
        });
}

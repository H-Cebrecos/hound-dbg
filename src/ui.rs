use std::path::Path;

use eframe::NativeOptions;
use egui::{Color32, FontData, FontDefinitions, FontFamily, RichText};

use crate::{App, ObjectFile, disasm::DisasmBinary, truncate_middle};

pub struct Ui {
    // Logic stuff
    app: App,

    // GUI stuff
    symbol_panel_open: bool,
    trace_panel_open: bool,
    fullscreen: bool,
    symbol_filter: String,
}
const THEME: catppuccin_egui::Theme = catppuccin_egui::FRAPPE;
impl Ui {
    pub fn new() -> Self {
        Ui {
            app: App {
                objects: Vec::new(),
                active_sym: None,
                active_file: None,
            },

            symbol_panel_open: false,
            trace_panel_open: false,
            fullscreen: false,
            symbol_filter: String::new(),
        }
    }

    pub fn run(self) {
        let options = NativeOptions::default();
        let _ = eframe::run_native(
            "Hound",
            options,
            Box::new(|cc| {
                let mut fonts = FontDefinitions::default();
                fonts.font_data.insert(
                    "mononoki".to_owned(),
                    FontData::from_static(include_bytes!(
                        "../assets/MononokiNerdFontMono-Regular.ttf"
                    ))
                    .into(),
                );
                fonts
                    .families
                    .entry(FontFamily::Monospace)
                    .or_default()
                    .insert(0, "mononoki".to_owned());
                fonts
                    .families
                    .entry(FontFamily::Proportional)
                    .or_default()
                    .insert(0, "mononoki".to_owned());
                cc.egui_ctx.set_fonts(fonts);
                Ok(Box::new(self))
            }),
        );
    }

    fn open_file(&mut self, path: &Path) {
        println!("Opening {}", path.display());

        // Detect whether it is an objetc or CTXP.
        if ctxp::Decoder::detect_format(path).is_ok() {
            let _event_dec = ctxp::Decoder::open(path).unwrap();
            //TODO: finish ctxp encoder so that we can generate a transcoder to text here.
            //Store the event collection somewhere.
        } else {
            if let Ok(disasm) = DisasmBinary::load(path) {
                self.symbol_panel_open = true;

                let name = path.file_stem().unwrap().to_string_lossy().into_owned();

                self.app.objects.push(ObjectFile { name, disasm });
            } else {
                //TODO: unsuported file
            }
        }
    }
}

impl eframe::App for Ui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // color theme
        catppuccin_egui::set_theme(&ctx, THEME);

        // fullscreen support
        if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
            self.fullscreen = !self.fullscreen;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
        }

        // drag & drop support
        ctx.input(|i| {
            // Files currently hovering over the window.
            for file in &i.raw.hovered_files {
                println!("hovering: {:?}", file.path);
            }

            // Files that were dropped this frame.
            for file in &i.raw.dropped_files {
                //TODO: check for duplicates, probably inside open_file
                self.open_file(&file.path.as_ref().unwrap().clone());
            }
        });

        egui::TopBottomPanel::top("top_bar")
            .show_separator_line(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("☰").size(24.)).clicked() {
                        self.symbol_panel_open = !self.symbol_panel_open;
                    }

                    let active_element = if let Some(file) = self.app.get_active_obj_name()
                        && let Some(sym) = self.app.get_active_sym_name()
                    {
                        format!("{} > {}", file, sym)
                    } else {
                        "Nothing selected".into()
                    };

                    ui.label(active_element);

                    ui.separator();
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(RichText::new("☰").size(24.)).clicked() {
                            self.trace_panel_open = !self.trace_panel_open;
                        }
                    });
                    //TODO: menu_button and menu_button_image exist and are likely very usefil.
                });
            });
        egui::SidePanel::left("sym_panel")
            .show_separator_line(false)
            .resizable(true)
            .default_width(400.0)
            .show_animated(ctx, self.symbol_panel_open, |ui| {
                // ---------- Header ----------
                ui.add(
                    egui::TextEdit::singleline(&mut self.symbol_filter)
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

                        let filter = self.symbol_filter.trim().to_ascii_lowercase();

                        for (file_idx, file) in &mut self.app.objects.iter().enumerate() {
                            let matching: Vec<_> = file
                                .disasm
                                .functions()
                                .filter(|sym| {
                                    filter.is_empty()
                                        || sym.name.to_ascii_lowercase().contains(&filter)
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
                            if let Some(active) = self.app.active_file
                                && active == file_idx
                            {
                                file_text = file_text.color(THEME.sky);
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

                                        if let Some(active_id) = self.app.active_sym
                                            && active_id == sym.addr
                                        {
                                            if let Some(active) = self.app.active_file
                                                && active == file_idx
                                            {
                                                text = text.strong().color(THEME.sky);
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
                                            self.app.active_sym = Some(sym.addr);
                                            self.app.active_file = Some(file_idx); //TODO
                                        }
                                    }
                                });
                        }
                    });
                });

                ui.scope_builder(egui::UiBuilder::new().max_rect(footer_rect), |ui| {
                    ui.separator();

                    if !self.app.objects.is_empty() {
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
                                self.open_file(&path)
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

        egui::SidePanel::right("trace_panel")
            .show_separator_line(false)
            .resizable(false)
            .default_width(400.0)
            .show_animated(ctx, self.trace_panel_open, |ui| {
                ui.horizontal(|ui| {
                           ui.checkbox(&mut true, "CPU0");
                           ui.checkbox(&mut true, "CPU1");
                           ui.checkbox(&mut false, "CPU2");
                           ui.checkbox(&mut true, "CPU3");

                           ui.separator();

                           let linked = true;
                           let text = if linked { "🔗" } else { "⛓" };

                           _ = ui.selectable_label(linked, text);
                       });

                       ui.separator();

                       egui::ScrollArea::vertical()
                           .stick_to_bottom(true)
                           .show(ui, |ui| {
                               ui.style_mut().override_text_style = Some(egui::TextStyle::Monospace);

                               ui.label(
                                   RichText::new("HDR:format=accemic//ctxp-txt,ver=1")
                                       .monospace()
                                       .color(THEME.subtext0),
                               );

                               ui.label(
                                   RichText::new(r#"META:#0="CPU0",#1="CPU1",#2="CPU2",#3="CPU3""#)
                                       .monospace()
                                       .color(THEME.subtext0),
                               );

                               ui.label(
                                   RichText::new("#0:MEMWRITE_1::0xfd7630b2a2ef6071")
                                       .monospace()
                                       .color(THEME.blue),
                               );

                               ui.label(
                                   RichText::new("#0:OVERFLOW::                                      @ 3426877816493824232")
                                       .monospace()
                                       .color(THEME.blue),
                               );

                               ui.label(
                                   RichText::new("#1:DAQ_COUNTER:0xa61dc1b0a5465bd3:0x191cb6         @ 11059482132507134706")
                                       .monospace()
                                       .color(THEME.green),
                               );

                               ui.label(
                                   RichText::new("#2:MEMREAD_1:0xd885b9d042c5f5bf:0x7f6b05ab76afa832 @ 1079037894117179173")
                                       .monospace()
                                       .color(THEME.yellow),
                               );

                               ui.label(
                                   RichText::new("#3:BRANCH_TAKEN:0x77167bf3be13f027:0x88c5bacb2698ccc0 @ 6063295116133120025")
                                       .monospace()
                                       .color(THEME.mauve),
                               );
                               // ...
                           });

            });

        let mut frame = egui::Frame::central_panel(&ctx.style());
        frame.fill = ctx.style().visuals.panel_fill.gamma_multiply(0.7);

        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            if self.app.objects.is_empty() {
                ui.centered_and_justified(|ui| {
                    let response = ui.add(
                        egui::Button::new(
                            egui::RichText::new("drag object file or click to search")
                                .italics()
                                .weak(),
                        )
                        .frame(false),
                    );

                    if response.clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.open_file(&path)
                        }
                    }
                });
            } else if self.app.active_sym.is_some() {
                egui::ScrollArea::vertical()
                    .id_salt("disasm_scroll")
                    .show(ui, |ui| {
                        ui.set_min_width(400.);
                        let (Some(file_idx), Some(addr)) =
                            (self.app.active_file, self.app.active_sym)
                        else {
                            return;
                        };
                        let Some(obj) = self.app.objects.get(file_idx) else {
                            return;
                        };
                        let Some(func) = obj.disasm.function_at_addr(addr) else {
                            return;
                        };

                        // One Vec<DepthCell> per row, collected across the whole function first.
                        let mut rows: Vec<Vec<DepthCell>> = Vec::new();
                        let marker_width = 10.0;
                        let row_height = ui.text_style_height(&egui::TextStyle::Monospace);

                        egui::Grid::new("disasm_grid")
                            .num_columns(4)
                            .striped(false)
                            .spacing([10.0, 4.0])
                            .show(ui, |ui| {
                                let mut last_chain: Vec<(String, u32)> = Vec::new();

                                for instr in &func {
                                    let frames = obj.disasm.frames_for_addr(instr.addr);

                                    let instr_text =
                                        instr.text.split(':').next_back().unwrap().trim();
                                    let mut parts = instr_text.splitn(2, char::is_whitespace);
                                    let mnemonic = parts.next().unwrap_or("");
                                    let operands = parts.next().unwrap_or("").trim();

                                    ui.label(RichText::new(format!("{:08x}", instr.addr)).weak());
                                    ui.label(RichText::new(mnemonic).monospace().color(THEME.blue));
                                    ui.label(operands);

                                    let chain: Vec<(String, u32)> = frames
                                        .iter()
                                        .rev()
                                        .map(|f| (f.function.clone(), f.line.unwrap_or(0)))
                                        .collect();

                                    // find first index where this chain diverges from the last one
                                    let first_diff = chain
                                        .iter()
                                        .zip(last_chain.iter())
                                        .position(|(a, b)| a != b)
                                        .unwrap_or_else(|| last_chain.len().min(chain.len()));

                                    let hover_lines: Vec<String> = Vec::new();
                                    let mut cells: Vec<DepthCell> = Vec::new();

                                    ui.horizontal(|ui| {
                                        for (depth, (function, line)) in chain.iter().enumerate() {
                                            let is_new = depth >= first_diff;

                                            let (rect, response) = ui.allocate_exact_size(
                                                egui::vec2(marker_width, row_height),
                                                egui::Sense::hover(),
                                            );

                                            if is_new {
                                                ui.painter().circle_filled(
                                                    rect.center(),
                                                    2.0,
                                                    THEME.overlay0.gamma_multiply(0.5),
                                                );

                                                let hover_text = format!("{function}:{line}");
                                                response
                                                    .on_hover_text(hover_text.clone())
                                                    .context_menu(|ui| {
                                                        if ui.button("Copy").clicked() {
                                                            ui.ctx().copy_text(hover_text.clone());
                                                            ui.close();
                                                        }
                                                    });
                                            }

                                            cells.push(DepthCell { rect, is_new });
                                        }
                                    });
                                    //TODO: UX can be improved here
                                    if !hover_lines.is_empty() {
                                        let hover_text = hover_lines.join("\n");
                                        ui.label("")
                                            .on_hover_text(hover_text.clone())
                                            .context_menu(|ui| {
                                                if ui.button("Copy").clicked() {
                                                    ui.ctx().copy_text(hover_text.clone());
                                                    ui.close();
                                                }
                                            });
                                    }
                                    ui.end_row();
                                    last_chain = chain;
                                    rows.push(cells);
                                }
                            });

                        // Second pass: for each depth, draw one continuous vertical segment per
                        // run — starting at a '-' row, extending through consecutive rows that
                        // still reach that depth, stopping when the chain no longer does.
                        let painter = ui.painter();
                        let max_depth = rows.iter().map(|r| r.len()).max().unwrap_or(0);

                        for depth in 0..max_depth {
                            let mut run_start: Option<usize> = None;

                            for (row_idx, row) in rows.iter().enumerate() {
                                match row.get(depth) {
                                    Some(cell) if cell.is_new => {
                                        // close any prior run, start a new one here
                                        if let Some(start) = run_start.take() {
                                            draw_run(painter, &rows, depth, start, row_idx - 1);
                                        }
                                        run_start = Some(row_idx);
                                    }
                                    Some(_cell) => {
                                        // continues — keep run_start as is
                                    }
                                    None => {
                                        // chain doesn't reach this depth anymore — close the run
                                        if let Some(start) = run_start.take() {
                                            draw_run(painter, &rows, depth, start, row_idx - 1);
                                        }
                                    }
                                }
                            }
                            if let Some(start) = run_start {
                                draw_run(painter, &rows, depth, start, rows.len() - 1);
                            }
                        }

                        ui.add_space(200.);
                    });
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("no symbol selected").italics().weak());
                });
            }

            egui::Area::new("replay_controls".into())
                .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -35.0))
                .show(ctx, |ui| {
                    egui::Frame::new()
                        .fill(ui.visuals().panel_fill)
                        .corner_radius(10.0)
                        .stroke(egui::Stroke::new(1.0, THEME.overlay1))
                        .shadow(egui::epaint::Shadow {
                            offset: [0, 4],
                            blur: 16,
                            spread: 0,
                            color: Color32::from_black_alpha(100),
                        })
                        .inner_margin(egui::Margin::symmetric(16, 8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                _ = ui.button("⏮");
                                _ = ui.button("⏪");
                                _ = ui.button("⏵");
                                _ = ui.button("⏸");
                                _ = ui.button("⏩");
                                _ = ui.button("⏭");
                            });
                        });
                });

            egui::TopBottomPanel::bottom("timeline")
                .show_separator_line(false)
                .show(ctx, |ui| {
                    //...
                    ui.set_height(28.0);

                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 28.0),
                        egui::Sense::hover(),
                    );

                    let painter = ui.painter();

                    // Background (whole trace)
                    painter.rect_filled(rect, 6.0, THEME.surface0);

                    // Highlighted regions
                    for (start, end, color) in [
                        (0.03, 0.06, THEME.blue),
                        (0.11, 0.13, THEME.red),
                        (0.18, 0.27, THEME.green),
                        (0.35, 0.37, THEME.yellow),
                        (0.42, 0.50, THEME.mauve),
                        (0.58, 0.61, THEME.peach),
                        (0.72, 0.80, THEME.teal),
                        (0.88, 0.91, THEME.maroon),
                    ] {
                        let x0 = egui::lerp(rect.left()..=rect.right(), start);
                        let x1 = egui::lerp(rect.left()..=rect.right(), end);

                        painter.rect_filled(
                            egui::Rect::from_min_max(
                                egui::pos2(x0, rect.top()),
                                egui::pos2(x1, rect.bottom()),
                            ),
                            2.0,
                            color,
                        );
                    }

                    // Current position marker
                    let cursor = egui::lerp(rect.left()..=rect.right(), 0.46);
                    painter.line_segment(
                        [
                            egui::pos2(cursor, rect.top() - 2.0),
                            egui::pos2(cursor, rect.bottom() + 2.0),
                        ],
                        egui::Stroke::new(2.0, THEME.text),
                    );
                });
        });
    }
}

struct DepthCell {
    rect: egui::Rect,
    is_new: bool, // true = '-' (run starts here), false = '|' (continues)
}

fn draw_run(
    painter: &egui::Painter,
    rows: &[Vec<DepthCell>],
    depth: usize,
    start_row: usize,
    end_row: usize,
) {
    if end_row <= start_row {
        return; // single-row run, nothing to connect
    }

    let start_gap = 1.0; // push start down, past the start
    let end_extra = 8.0; // push end further down, past the last row's center

    let x = rows[start_row][depth].rect.center().x;
    let y0 = rows[start_row][depth].rect.center().y + start_gap;
    let y1 = rows[end_row][depth].rect.center().y + end_extra;

    painter.line_segment(
        [egui::pos2(x, y0), egui::pos2(x, y1)],
        egui::Stroke::new(1., THEME.overlay0.gamma_multiply(0.5)),
    );
}

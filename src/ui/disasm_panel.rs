use egui::{Color32, Context, RichText};

pub fn disasm_panel(ctx: &Context, ui_app: &mut super::Ui) {
    let mut frame = egui::Frame::central_panel(&ctx.style());
    frame.fill = ctx.style().visuals.panel_fill.gamma_multiply(0.7);

    egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
        if ui_app.app.objects.is_empty() {
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
                        ui_app.open_file(&path)
                    }
                }
            });
        } else if ui_app.app.active.is_some() {
            egui::ScrollArea::vertical()
                .id_salt("disasm_scroll")
                .show(ui, |ui| {
                    ui.set_min_width(400.);
                    let Some(sel) = ui_app.app.active else {
                        ui.centered_and_justified(|ui| {
                            ui.label(RichText::new("no symbol selected").italics().weak());
                        });
                        return;
                    };
                    let Some(obj) = ui_app.app.objects.get_mut(sel.obj) else {
                        return;
                    };
                    let Some(func) = obj.disasm.function_at_addr(sel.addr) else {
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

                                let instr_text = instr.text.split(':').next_back().unwrap().trim();
                                let mut parts = instr_text.splitn(2, char::is_whitespace);
                                let mnemonic = parts.next().unwrap_or("");
                                let operands = parts.next().unwrap_or("").trim();

                                ui.label(RichText::new(format!("{:08x}", instr.addr)).weak());
                                ui.label(
                                    RichText::new(mnemonic).monospace().color(super::THEME.blue),
                                );
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
                                                super::THEME.overlay0.gamma_multiply(0.5),
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
                                    ui.label("").on_hover_text(hover_text.clone()).context_menu(
                                        |ui| {
                                            if ui.button("Copy").clicked() {
                                                ui.ctx().copy_text(hover_text.clone());
                                                ui.close();
                                            }
                                        },
                                    );
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
                    .stroke(egui::Stroke::new(1.0, super::THEME.overlay1))
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
                painter.rect_filled(rect, 6.0, super::THEME.surface0);

                // Highlighted regions
                for (start, end, color) in [
                    (0.03, 0.06, super::THEME.blue),
                    (0.11, 0.13, super::THEME.red),
                    (0.18, 0.27, super::THEME.green),
                    (0.35, 0.37, super::THEME.yellow),
                    (0.42, 0.50, super::THEME.mauve),
                    (0.58, 0.61, super::THEME.peach),
                    (0.72, 0.80, super::THEME.teal),
                    (0.88, 0.91, super::THEME.maroon),
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
                    egui::Stroke::new(2.0, super::THEME.text),
                );
            });
    });
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
        egui::Stroke::new(1., super::THEME.overlay0.gamma_multiply(0.5)),
    );
}

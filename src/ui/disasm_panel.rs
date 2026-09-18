//! Disassembly panel.
//!
//! Renders the instructions of the selected function. Three layers of
//! annotation sit around the instruction text, from left to right:
//!
//! 1. Jump arrows — for branches that stay inside the function, a lane
//!    diagram connecting each branch to the instruction it targets.
//! 2. The breakpoint gutter and address.
//! 3. The inlining markers, and to their right the symbol name a direct
//!    branch or call resolves to, when the target is a known symbol.
//!
//! Both diagrams are drawn the same way: the grid pass records a rect per
//! row while laying out the text, and a second pass paints the connecting
//! lines over those rects once every row's position is known.

use egui::{Color32, Context, RichText};

use crate::disasm::DisasmFunction;

/// Horizontal space taken by one jump-arrow lane.
const LANE_WIDTH: f32 = 6.0;

/// Lanes beyond this share the outermost one, bounding how much horizontal
/// space a densely branching function can claim.
const MAX_LANES: usize = 6;

pub fn disasm_panel(ctx: &Context, ui_app: &mut super::Ui) {
    let mut frame = egui::Frame::central_panel(&ctx.style());
    frame.fill = ctx.style().visuals.panel_fill.gamma_multiply(0.7);

    // Navigation requested from inside the panel (clicking a resolved branch
    // target), applied once the panel has released its borrow on the object.
    let mut nav_request: Option<u64> = None;
    let scroll_to = ui_app.scroll_to.take();

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
                .auto_shrink([true, false])
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
                    let disasm = &obj.disasm;
                    let breakpoints = &mut obj.breakpoints;

                    let marker_width = 10.0;

                    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);

                    // Jumps that stay inside this function, laid out into
                    // non-overlapping lanes before anything is drawn.
                    let jumps = JumpLanes::of(&func);
                    let mut jump_rects: Vec<egui::Rect> = Vec::new();

                    egui::Grid::new("disasm_grid")
                        .num_columns(if jumps.is_empty() { 5 } else { 6 })
                        .striped(false)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            let mut last_chain: Vec<(String, u32)> = Vec::new();

                            for (row_idx, instr) in (&func).into_iter().enumerate() {
                                let frames = disasm.frames_for_addr(instr.addr);

                                let instr_text = instr.text.split(':').next_back().unwrap().trim();
                                let mut parts = instr_text.splitn(2, char::is_whitespace);
                                let mnemonic = parts.next().unwrap_or("");
                                let operands = parts.next().unwrap_or("").trim();

                                // ---------- Jump arrow gutter ----------
                                if !jumps.is_empty() {
                                    let (rect, _) = ui.allocate_exact_size(
                                        egui::vec2(jumps.width(), row_height),
                                        egui::Sense::hover(),
                                    );
                                    jump_rects.push(rect);
                                }

                                // ---------- Breakpoint gutter + address, tightly grouped ----------
                                let addr_cell = ui
                                    .horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 4.0;

                                        let bp_size = 14.0; // fixed, independent of text height
                                        let (bp_rect, bp_response) = ui.allocate_exact_size(
                                            egui::vec2(bp_size, row_height),
                                            egui::Sense::click(),
                                        );
                                        let has_bp = breakpoints.contains(&instr.addr);
                                        if has_bp {
                                            ui.painter().circle_filled(
                                                bp_rect.center(),
                                                4.0,
                                                super::THEME.red,
                                            );
                                        } else if bp_response.hovered() {
                                            ui.painter().circle_stroke(
                                                bp_rect.center(),
                                                4.0,
                                                egui::Stroke::new(
                                                    1.0,
                                                    super::THEME.red.gamma_multiply(0.5),
                                                ),
                                            );
                                        }
                                        if bp_response.clicked() {
                                            if has_bp {
                                                breakpoints.remove(&instr.addr);
                                            } else {
                                                breakpoints.insert(instr.addr);
                                            }
                                        }

                                        ui.label(
                                            RichText::new(format!("{:08x}", instr.addr)).weak(),
                                        );
                                    })
                                    .response;

                                // Requested from another panel: bring the
                                // instruction into view once it has a rect.
                                if scroll_to == Some(instr.addr) {
                                    addr_cell.scroll_to_me(Some(egui::Align::Center));
                                }

                                ui.label(RichText::new(mnemonic).color(super::THEME.blue));
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

                                // ---------- Resolved branch target ----------
                                // Only direct transfers to an address that is
                                // itself a known symbol get a name; anything
                                // else (indirect, or a target inside some
                                // function) is left blank.
                                match instr.kind.target().and_then(|t| disasm.symbol_at(t)) {
                                    Some(name) => {
                                        let label = ui.selectable_label(
                                            false,
                                            RichText::new(format!(
                                                "→ {}",
                                                super::sym_panel::truncate_middle(name, 48)
                                            ))
                                            .color(super::THEME.green),
                                        );

                                        if label.on_hover_text(name).clicked() {
                                            nav_request = instr.kind.target();
                                        }
                                    }
                                    None => {
                                        ui.label("");
                                    }
                                }

                                ui.end_row();
                                last_chain = chain;
                                rows.push(cells);
                                // row_idx currently unused beyond enumerate bookkeeping;
                                // kept for clarity/debuggability if needed later.
                                let _ = row_idx;
                            }
                        });

                    // ---------- Second pass: jump arrows ----------
                    jumps.draw(ui.painter(), &jump_rects);

                    // ---------- Second pass: call-chain depth connectors (unchanged) ----------
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

    // Follow a clicked branch target, in the object the panel was showing.
    if let Some(addr) = nav_request
        && let Some(sel) = ui_app.app.active
    {
        ui_app.reveal(sel.obj, addr);
    }
}

struct DepthCell {
    rect: egui::Rect,
    is_new: bool, // true = 'dot' (run starts here), false = '|' (continues)
}

/// One branch that stays inside the displayed function, as row indices into
/// the rendered instruction list.
struct Jump {
    from: usize,
    to: usize,
    /// Which vertical lane this jump's line is drawn in; lane 0 sits
    /// closest to the instruction text.
    lane: usize,
}

/// The intra-function jumps of one function, assigned to lanes so that no
/// two overlapping jumps share a vertical line.
struct JumpLanes {
    jumps: Vec<Jump>,
    lane_count: usize,
}

impl JumpLanes {
    /// Collect the branches of `func` whose target is another instruction
    /// of the same function, and lay them out.
    ///
    /// Calls are excluded: they come back, so drawing them as a jump inside
    /// the function would be misleading — a call's destination is shown by
    /// name instead.
    fn of(func: &DisasmFunction<'_>) -> Self {
        let addrs: Vec<u64> = func.instructions().map(|i| i.addr).collect();

        let mut jumps: Vec<Jump> = func
            .instructions()
            .enumerate()
            .filter_map(|(row, instr)| {
                if instr.kind.is_call() {
                    return None;
                }

                let target = instr.kind.target()?;
                // Instruction addresses are sorted, and a target that isn't
                // one of them is outside the function (or misaligned).
                let to = addrs.binary_search(&target).ok()?;

                (to != row).then_some(Jump {
                    from: row,
                    to,
                    lane: 0,
                })
            })
            .collect();

        // Shortest first, so tight loops get the innermost lanes and long
        // jumps arc around them.
        jumps.sort_by_key(|j| j.from.abs_diff(j.to));

        // Greedy lane assignment: reuse the innermost lane whose occupied
        // spans don't overlap this jump.
        let mut lanes: Vec<Vec<(usize, usize)>> = Vec::new();
        for jump in &mut jumps {
            let (lo, hi) = (jump.from.min(jump.to), jump.from.max(jump.to));

            let lane = lanes
                .iter()
                .position(|spans| spans.iter().all(|&(a, b)| hi < a || lo > b))
                .unwrap_or_else(|| {
                    lanes.push(Vec::new());
                    lanes.len() - 1
                });

            lanes[lane].push((lo, hi));
            jump.lane = lane.min(MAX_LANES - 1);
        }

        Self {
            jumps,
            lane_count: lanes.len().min(MAX_LANES),
        }
    }

    fn is_empty(&self) -> bool {
        self.jumps.is_empty()
    }

    /// Width the gutter needs, including the stub that joins the outermost
    /// lane to the instruction it points at.
    fn width(&self) -> f32 {
        (self.lane_count + 1) as f32 * LANE_WIDTH
    }

    /// Paint the arrows over the per-row rects recorded during layout.
    fn draw(&self, painter: &egui::Painter, row_rects: &[egui::Rect]) {
        let stroke = egui::Stroke::new(1.0, super::THEME.overlay1.gamma_multiply(0.8));

        for jump in &self.jumps {
            let (Some(from), Some(to)) = (row_rects.get(jump.from), row_rects.get(jump.to)) else {
                continue;
            };

            // Lane 0 is nearest the text, i.e. rightmost in the gutter.
            let x = from.right() - (jump.lane + 1) as f32 * LANE_WIDTH;
            let (y0, y1) = (from.center().y, to.center().y);

            painter.line_segment([egui::pos2(x, y0), egui::pos2(from.right(), y0)], stroke);
            painter.line_segment([egui::pos2(x, y0), egui::pos2(x, y1)], stroke);
            painter.line_segment([egui::pos2(x, y1), egui::pos2(to.right(), y1)], stroke);

            // Arrow head at the target, pointing into the instruction.
            let tip = egui::pos2(to.right(), y1);
            for dy in [-3.0, 3.0] {
                painter.line_segment([egui::pos2(tip.x - 4.0, tip.y + dy), tip], stroke);
            }
        }
    }
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

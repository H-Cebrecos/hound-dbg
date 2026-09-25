//! Symbol panel.
//!
//! Renders the left-hand [`sym_panel`] widget: a per-object, collapsible
//! list of the function symbols discovered in each loaded [`ObjectFile`],
//! with search and selection.
//!
//! # Search
//!
//! The filter box in supports three modes, tried in
//! order:
//! 1. A hex address (with or without `0x`/`0X` prefix) — matches symbols
//!    whose range contains that address.
//! 2. Otherwise, fast subsequence matching against the
//!    canonical name and every alias.
//! 3. If nothing subsequence-matches, a typo-tolerant fallback
//!    over the same names.
//!
//! # Aliases
//!
//! Multiple symbols can share an address (weak/strong alias pairs,
//! versioned symbols, hand-written assembly with several entry labels).
//! Rather than showing one row per symbol, each unique address is shown
//! once under its canonical name (see [`DisasmFunction::name`]), with the
//! remaining aliases surfaced via a `+N` badge, hover tooltip, and a
//! "copy all aliases" context-menu action.
//!
//! # Selection
//!
//! Clicking a symbol sets [`App::active`], which
//! the disassembly panel reads to decide what to render.
//!
//! # Objects
//!
//! Object files are added from the panel footer (or by dropping them on the
//! window) and unloaded from the ✕ on their header. Both paths go through
//! [`Ui::open_file`](super::Ui::open_file) / [`Ui::remove_object`](super::Ui::remove_object)
//! so that selections and caller searches stay consistent with the object
//! list.

use egui::{Color32, Context, RichText};
use fuzzy_matcher::{skim::SkimMatcherV2, *};

use crate::{Location, ObjectKey, disasm::DisasmFunction};

/// Render the symbol panel
pub fn sym_panel(ctx: &Context, ui_app: &mut super::Ui) {
    egui::SidePanel::left("sym_panel")
        .show_separator_line(false)
        .resizable(true)
        .default_width(400.0)
        .show_animated(ctx, ui_app.symbol_panel_open, |ui| {
            // ---------- Search Bar ----------
            ui.add(
                egui::TextEdit::singleline(&mut ui_app.symbol_filter)
                    .hint_text("Search symbols... (name or address)")
                    .desired_width(f32::INFINITY),
            );

            if ui
                .add_enabled(ui_app.app.active.is_some(), egui::Button::new("🎯"))
                .on_hover_text("Scroll to selected symbol")
                .clicked()
            {
                ui_app.scroll_to_active = true;
            };

            // -------- Rect computations --------
            let footer_height = 32.0;

            let mut body_rect = ui.available_rect_before_wrap();
            body_rect.max.y -= footer_height;

            let mut footer_rect = ui.available_rect_before_wrap();
            footer_rect.min.y = footer_rect.max.y - footer_height;

            // Applied once the walk below has released its borrow on the
            // object list.
            let mut unload: Option<ObjectKey> = None;
            let mut find_callers: Option<(ObjectKey, u64)> = None;

            // -------- Main View --------
            ui.scope_builder(egui::UiBuilder::new().max_rect(body_rect), |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let filter = ui_app.symbol_filter.trim();

                    // Captured once: the loop mutably borrows ui_app, so we can't
                    // re-check/clear this mid-walk. `did_scroll` tracks whether this
                    // frame actually performed the scroll, so we know to clear the
                    // request afterwards.
                    let want_scroll = ui_app.scroll_to_active;
                    let mut did_scroll = false;

                    for (key, obj) in &mut ui_app.app.objects.iter() {
                        let filtered_syms =
                            filter_symbols(obj.disasm.functions(), filter, &ui_app.symbol_matcher);

                        // If obj has no matching functions don't display the object
                        if filtered_syms.is_empty() {
                            continue;
                        }

                        let mut obj_name = RichText::new(&obj.name).heading();
                        // highlight if selected
                        let is_active_obj =
                            matches!(ui_app.app.active, Some(Location { obj, .. }) if obj == key);
                        if is_active_obj {
                            obj_name = obj_name.strong().color(super::THEME.mauve);
                        }

                        // Per object collapsable
                        let id = ui.make_persistent_id(&obj.name);
                        let mut collapsing =
                            egui::collapsing_header::CollapsingState::load_with_default_open(
                                ui.ctx(),
                                id,
                                true,
                            );

                        // If we're focusing and the active symbol lives in this
                        // (possibly collapsed) object, force it open so the row we're
                        // about to scroll to actually exists this frame.
                        if want_scroll && is_active_obj {
                            collapsing.set_open(true);
                        }

                        collapsing
                            // header styling
                            .show_header(ui, |ui| {
                                ui.label(obj_name.clone());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .add(
                                                egui::Button::new(RichText::new("✕").weak())
                                                    .frame(false),
                                            )
                                            .on_hover_text(format!("Unload {}", obj.name))
                                            .clicked()
                                        {
                                            unload = Some(key);
                                        }

                                        ui.add_space(10.);

                                        let count_text =
                                            format!("{} functions", obj.disasm.functions().count());

                                        // Measure how wide the count label would be, without drawing it,
                                        // so we can decide whether it fits before committing to show it.
                                        let font_id = egui::TextStyle::Body.resolve(ui.style());
                                        let galley = ui.painter().layout_no_wrap(
                                            count_text.clone(),
                                            font_id,
                                            ui.visuals().text_color(),
                                        );

                                        // Avoid function count overlapping the object name.
                                        if ui.available_width() > galley.size().x {
                                            ui.label(RichText::new(count_text).weak());
                                        }
                                    },
                                );
                            })
                            // Symbols
                            .body(|ui| {
                                for sym in filtered_syms {
                                    let mut text = RichText::new(truncate_middle(
                                        sym.name,
                                        (ui.available_width() / 8.) as usize,
                                    ))
                                    .weak();

                                    // Highlight if selected
                                    let is_active_sym = ui_app.app.active
                                        == Some(Location {
                                            obj: key,
                                            addr: sym.addr,
                                        });

                                    if is_active_sym {
                                        text = text.strong().color(super::THEME.mauve);
                                    }

                                    let extra_aliases = sym.aliases.len().saturating_sub(1);

                                    let clickable_sym = ui
                                        .horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 4.0;
                                            let label = ui.selectable_label(false, text);

                                            if extra_aliases > 0 {
                                                ui.label(
                                                    RichText::new(format!("+{extra_aliases}"))
                                                        .weak()
                                                        .color(
                                                            super::THEME
                                                                .overlay1
                                                                .gamma_multiply(0.5),
                                                        ),
                                                );
                                            }

                                            label
                                        })
                                        .inner
                                        //this instead of on_hover_text to prevent very long symbol names from wrapping as well as for multi-color
                                        .on_hover_ui(|ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    RichText::new(format!("0x{:x}:", sym.addr))
                                                        .weak(),
                                                );
                                                ui.label(sym.name);
                                            });

                                            if extra_aliases > 0 {
                                                ui.separator();
                                                ui.label(
                                                    RichText::new("Symbol aliases:")
                                                        .weak()
                                                        .italics(),
                                                );
                                                for alias in sym.aliases.get(1..).unwrap_or(&[]) {
                                                    ui.label(RichText::new(alias));
                                                }
                                            }
                                        });

                                    if is_active_sym && want_scroll {
                                        clickable_sym.scroll_to_me(Some(egui::Align::Center));
                                        did_scroll = true;
                                    }

                                    clickable_sym.context_menu(|ui| {
                                        if ui.button("Copy symbol name").clicked() {
                                            ui.ctx().copy_text(sym.name.to_owned());
                                        }
                                        if ui.button("Copy symbol address").clicked() {
                                            ui.ctx().copy_text(format!("{:x}", sym.addr));
                                        }
                                        if extra_aliases > 0
                                            && ui.button("Copy all aliases").clicked()
                                        {
                                            ui.ctx().copy_text(sym.aliases.join("\n"));
                                        }
                                        ui.separator();
                                        if ui.button("Find callers").clicked() {
                                            find_callers = Some((key, sym.addr));
                                            ui.close();
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
                                    });

                                    // If clicked select as active
                                    if clickable_sym.clicked() {
                                        ui_app.app.active = Some(Location {
                                            obj: key,
                                            addr: sym.addr,
                                        });
                                    }
                                }
                            });
                    }

                    // Deferred: clear the one-shot focus request now that the walk
                    // (which held the mutable borrow of ui_app) has finished.
                    if did_scroll {
                        ui_app.scroll_to_active = false;
                    }
                });
            });

            // -------- Deferred object actions --------
            if let Some((obj_idx, addr)) = find_callers {
                ui_app.find_callers(obj_idx, addr);
            }

            if let Some(obj_idx) = unload {
                ui_app.remove_object(obj_idx);
            }

            // -------- Open File Prompt --------
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
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
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

/// Filter and rank a file's symbols against the user's search text.
///
/// - Empty filter: returns every symbol, unranked.
/// - Filter parses as a hex address (with or without `0x`/`0X` prefix):
///   returns symbols whose range contains that address, tightest match first.
/// - Otherwise: fuzzy-matches against symbol names, best match first.
fn filter_symbols<'a>(
    functions: impl Iterator<Item = DisasmFunction<'a>>,
    filter: &str,
    matcher: &SkimMatcherV2,
) -> Vec<DisasmFunction<'a>> {
    if filter.is_empty() {
        return functions.collect();
    }

    if let Some(addr) = parse_hex_addr(filter) {
        let mut matches: Vec<_> = functions.filter(|f| f.contains(addr)).collect();
        matches.sort_by_key(|f| f.size);
        return matches;
    }

    let functions: Vec<_> = functions.collect();

    // Primary: fast, order-preserving subsequence matching, checked against
    // the canonical name and every alias — best score per symbol wins, so
    // a symbol appears once even if a less-prominent alias is the match.
    let mut scored: Vec<(i64, usize)> = functions
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let best = f
                .aliases
                .iter()
                .filter_map(|name| matcher.fuzzy_match(name, filter))
                .max();
            best.map(|score| (score, i))
        })
        .collect();

    if !scored.is_empty() {
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        return scored.into_iter().map(|(_, i)| functions[i]).collect();
    }

    // Fallback: nothing subsequence-matched — try typo-tolerant matching
    // instead, in case the filter has a transposition/substitution/typo
    // relative to the canonical name or one of its aliases.
    const TYPO_THRESHOLD: f64 = 0.75;
    let filter_lower = filter.to_lowercase();
    let mut typo_scored: Vec<(f64, usize)> = functions
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let best = f
                .aliases
                .iter()
                .map(|name| strsim::jaro_winkler(&name.to_lowercase(), &filter_lower))
                .fold(0.0_f64, f64::max);
            (best > TYPO_THRESHOLD).then_some((best, i))
        })
        .collect();
    typo_scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    typo_scored.into_iter().map(|(_, i)| functions[i]).collect()
}

/// Parse `filter` as a hex address accepting an optional `0x`/`0X` prefix
/// (e.g. "1a2b", "0x1a2b", "0X1A2B" all parse to the same value).
fn parse_hex_addr(filter: &str) -> Option<u64> {
    let hex_part = filter
        .strip_prefix("0x")
        .or_else(|| filter.strip_prefix("0X"))
        .unwrap_or(filter);

    u64::from_str_radix(hex_part, 16).ok()
}

/// Truncate the middle of a string to reduce its display size while preserving start/end
/// This is used as symbol information is usually at the start/end for very long symbols
/// with most of the middle being namespace paths.
pub(super) fn truncate_middle(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }

    let keep = (max - 1) / 2;

    format!(
        "{}…{}",
        s.chars().take(keep).collect::<String>(),
        s.chars()
            .rev()
            .take(keep)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>(),
    )
}

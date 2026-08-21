use egui::{Color32, Context, RichText};
use fuzzy_matcher::{FuzzyMatcher, skim::SkimMatcherV2};

use crate::{disasm::DisasmFunction, truncate_middle};

pub fn sym_panel(ctx: &Context, ui_app: &mut super::Ui) {
    egui::SidePanel::left("sym_panel")
        .show_separator_line(false)
        .resizable(true)
        .default_width(400.0)
        .show_animated(ctx, ui_app.symbol_panel_open, |ui| {
            // ---------- Header ----------
            ui.add(
                egui::TextEdit::singleline(&mut ui_app.symbol_filter)
                    .hint_text("Search symbols... (name, alias, or address)")
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

                    let filter = ui_app.symbol_filter.trim();

                    for (file_idx, file) in &mut ui_app.app.objects.iter().enumerate() {
                        let matching =
                            filter_symbols(file.disasm.functions(), filter, &ui_app.symbol_matcher);

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
                            file_text = file_text.color(super::THEME.mauve);
                        }
                        egui::CollapsingHeader::new(file_text)
                            .id_salt(id)
                            .default_open(!filter.is_empty())
                            .show(ui, |ui| {
                                for sym in matching {
                                    let mut text = RichText::new(truncate_middle(
                                        sym.name,
                                        (ui.available_width() / 8.) as usize,
                                    ))
                                    .weak();

                                    if let Some(active_id) = ui_app.app.active_sym
                                        && active_id == sym.addr
                                    {
                                        if let Some(active) = ui_app.app.active_file
                                            && active == file_idx
                                        {
                                            text = text.strong().color(super::THEME.mauve);
                                        }
                                    }

                                    let extra_aliases = sym.aliases.len().saturating_sub(1);

                                    let response = ui
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
                                                    RichText::new("Also known as:")
                                                        .weak()
                                                        .italics(),
                                                );
                                                for alias in sym.aliases.get(1..).unwrap_or(&[]) {
                                                    ui.label(RichText::new(alias));
                                                }
                                            }
                                        });

                                    response.context_menu(|ui| {
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

/// Parse `filter` as a hex address, accepting an optional `0x`/`0X` prefix
/// (e.g. "1a2b", "0x1a2b", "0X1A2B" all parse to the same value).
fn parse_hex_addr(filter: &str) -> Option<u64> {
    let hex_part = filter
        .strip_prefix("0x")
        .or_else(|| filter.strip_prefix("0X"))
        .unwrap_or(filter);

    u64::from_str_radix(hex_part, 16).ok()
}

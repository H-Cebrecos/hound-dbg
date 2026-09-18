//! Caller lookup results.
//!
//! Answers "which functions call this one?" for the symbol selected in the
//! [`sym_panel`](super::sym_panel), by scanning the object's decoded
//! instruction stream for direct transfers into the symbol's entry point
//! (see [`DisasmBinary::callers_of`]).
//!
//! The scan runs once, when the action is invoked, and its results are kept
//! resolved to names here — the panel itself never re-queries while it is
//! open. Every row navigates: clicking a caller selects it in the
//! disassembly panel and scrolls to the call instruction.

use egui::{Context, RichText};

use crate::{
    Location, ObjectFile, ObjectKey,
    disasm::{CallSite, DisasmBinary},
};

/// A completed caller query, together with everything needed to display it
/// without borrowing back into the object it was run against.
pub struct CallerSearch {
    /// Object the query was run against.
    pub obj: ObjectKey,

    /// Entry address of the function whose callers these are.
    target_addr: u64,

    target_name: String,

    /// One entry per calling function, in address order.
    callers: Vec<Caller>,
}

/// One function that calls the target, with every site inside it.
struct Caller {
    addr: u64,
    name: String,
    sites: Vec<CallSite>,
}

impl CallerSearch {
    /// Scan `object` for calls to the function entry at `target` and group
    /// the results by calling function.
    pub fn run(obj: ObjectKey, object: &ObjectFile, target: u64) -> Self {
        let disasm = &object.disasm;

        let target_name = disasm
            .symbol_at(target)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{target:#x}"));

        // `callers_of` walks functions in address order, so sites belonging
        // to the same caller arrive together.
        let mut callers: Vec<Caller> = Vec::new();
        for site in disasm.callers_of(target) {
            match callers.last_mut() {
                Some(caller) if caller.addr == site.caller_addr => caller.sites.push(site),
                _ => callers.push(Caller {
                    addr: site.caller_addr,
                    name: caller_name(disasm, site.caller_addr),
                    sites: vec![site],
                }),
            }
        }

        Self {
            obj,
            target_addr: target,
            target_name,
            callers,
        }
    }

    fn site_count(&self) -> usize {
        self.callers.iter().map(|c| c.sites.len()).sum()
    }
}

/// Display name for a caller's entry address. Every address handed to this
/// came from a function entry, so the fallback is defensive only.
fn caller_name(disasm: &DisasmBinary, addr: u64) -> String {
    disasm
        .symbol_at(addr)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{addr:#x}"))
}

/// Render the caller results window, if a search is active.
pub fn callers_panel(ctx: &Context, ui_app: &mut super::Ui) {
    let active = ui_app.app.active;

    let Some(search) = &ui_app.callers else {
        return;
    };

    // Collected inside the window, applied after it closes, so the panel
    // never mutates the app while it is borrowing the search results.
    let mut navigate_to: Option<u64> = None;
    let mut open = true;

    egui::Window::new(RichText::new("Callers").heading())
        .id("callers_panel".into())
        .open(&mut open)
        .resizable(true)
        .default_width(360.0)
        .default_height(320.0)
        .show(ctx, |ui| {
            // ---------- What was searched for ----------
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(RichText::new("callers of").weak().italics());
                ui.label(
                    RichText::new(&search.target_name)
                        .strong()
                        .color(super::THEME.mauve),
                )
                .on_hover_text(format!("{:#x}", search.target_addr));
            });

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(RichText::new(plural(search.callers.len(), "function")).weak());
                ui.label(RichText::new("·").weak());
                ui.label(RichText::new(plural(search.site_count(), "call site")).weak());
            });

            ui.separator();

            if search.callers.is_empty() {
                ui.label(
                    RichText::new("No direct calls to this symbol were found")
                        .italics()
                        .weak(),
                );
                return;
            }

            // ---------- One row per calling function ----------
            egui::ScrollArea::vertical()
                .id_salt("callers_scroll")
                .show(ui, |ui| {
                    for caller in &search.callers {
                        let selected = active
                            == Some(Location {
                                obj: search.obj,
                                addr: caller.addr,
                            });

                        let mut text = RichText::new(super::sym_panel::truncate_middle(
                            &caller.name,
                            (ui.available_width() / 8.) as usize,
                        ));
                        if selected {
                            text = text.strong().color(super::THEME.mauve);
                        }

                        let row = ui
                            .horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 4.0;
                                let label = ui.selectable_label(selected, text);

                                if caller.sites.len() > 1 {
                                    ui.label(
                                        RichText::new(format!("×{}", caller.sites.len()))
                                            .weak()
                                            .color(super::THEME.overlay1),
                                    );
                                }

                                if caller.sites.iter().all(|s| s.tail) {
                                    ui.label(
                                        RichText::new("tail")
                                            .weak()
                                            .italics()
                                            .color(super::THEME.overlay1),
                                    )
                                    .on_hover_text(
                                        "reached by a branch to the symbol's entry point",
                                    );
                                }

                                label
                            })
                            .inner
                            .on_hover_text(&caller.name);

                        if row.clicked() {
                            navigate_to = Some(caller.sites[0].site_addr);
                        }

                        row.context_menu(|ui| {
                            if ui.button("Copy caller name").clicked() {
                                ui.ctx().copy_text(caller.name.clone());
                                ui.close();
                            }

                            if ui.button("Copy call site addresses").clicked() {
                                let addrs: Vec<_> = caller
                                    .sites
                                    .iter()
                                    .map(|s| format!("{:x}", s.site_addr))
                                    .collect();
                                ui.ctx().copy_text(addrs.join("\n"));
                                ui.close();
                            }
                        });

                        // Individual call sites, so a function calling the
                        // target several times stays navigable.
                        ui.horizontal_wrapped(|ui| {
                            ui.add_space(16.0);
                            ui.spacing_mut().item_spacing.x = 6.0;

                            for site in &caller.sites {
                                let site_label = ui.selectable_label(
                                    false,
                                    RichText::new(format!("{:08x}", site.site_addr))
                                        .weak()
                                        .monospace(),
                                );

                                if site_label.clicked() {
                                    navigate_to = Some(site.site_addr);
                                }
                            }
                        });
                    }
                });
        });

    if let Some(addr) = navigate_to {
        let obj = search.obj;
        ui_app.reveal(obj, addr);
    }

    if !open {
        ui_app.callers = None;
    }
}

/// "1 function" / "3 functions"
fn plural(count: usize, noun: &str) -> String {
    match count {
        1 => format!("1 {noun}"),
        n => format!("{n} {noun}s"),
    }
}

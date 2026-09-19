use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use eframe::NativeOptions;
use egui::{FontData, FontDefinitions, FontFamily, RichText};
use fuzzy_matcher::skim::SkimMatcherV2;
use slotmap::SlotMap;

use crate::{App, Location, ObjectFile, ObjectKey, disasm::DisasmBinary, trace_file::TraceFile};

use callers_panel::CallerSearch;

mod break_panel;
mod callers_panel;
mod disasm_panel;
mod sym_panel;
mod trace_panel;

const THEME: catppuccin_egui::Theme = catppuccin_egui::FRAPPE;

pub struct Ui {
    // Logic stuff
    app: App,

    // GUI stuff
    symbol_panel_open: bool,
    trace_panel_open: bool,
    break_panel_open: bool,
    fullscreen: bool,
    symbol_filter: String,
    symbol_matcher: SkimMatcherV2,
    source_active: HashMap<u8, bool>,

    /// Result of the most recent "find callers" action, if it hasn't been
    /// dismissed yet.
    callers: Option<CallerSearch>,

    /// Address the disassembly panel should scroll into view on the next
    /// frame, set when navigating from another panel. Cleared once used.
    scroll_to: Option<u64>,
}

impl Ui {
    pub fn new() -> Self {
        Ui {
            app: App {
                objects: SlotMap::with_key(),
                active: None,
                trace: None,
            },
            symbol_panel_open: false,
            trace_panel_open: false,
            break_panel_open: false,
            fullscreen: false,
            symbol_filter: String::new(),
            symbol_matcher: SkimMatcherV2::default(),
            source_active: HashMap::new(),
            callers: None,
            scroll_to: None,
        }
    }

    pub fn run(self) {
        let options = NativeOptions::default();
        let _ = eframe::run_native(
            "Hound",
            options,
            Box::new(|cc| {
                cc.egui_ctx.set_fonts(Self::load_fonts());
                Ok(Box::new(self))
            }),
        );
    }

    fn load_fonts() -> FontDefinitions {
        let mut fonts = FontDefinitions::default();

        fonts.font_data.insert(
            "mononoki".to_owned(),
            FontData::from_static(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/assets/MononokiNerdFontMono-Regular.ttf"
            )))
            .into(),
        );

        for family in [FontFamily::Monospace, FontFamily::Proportional] {
            fonts
                .families
                .entry(family)
                .or_default()
                .insert(0, "mononoki".to_owned());
        }

        fonts
    }

    fn open_file(&mut self, path: &Path) {
        println!("Opening {}", path.display());

        // Detect whether it is an object file or CTXP.
        if ctxp::Decoder::detect_format(path).is_ok() {
            match TraceFile::load(path) {
                Ok(trace) => {
                    for src in trace.sources() {
                        self.source_active.insert(src.id, true);
                    }
                    self.app.trace = Some(trace);
                }
                Err(e) => eprintln!("{:?}", e),
            }
        } else {
            match DisasmBinary::load(path) {
                Ok(disasm) => {
                    let name = path
                        .file_stem()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    self.app.objects.insert(ObjectFile {
                        path: path.into(),
                        name,
                        disasm,
                        breakpoints: HashSet::new(),
                    });
                    self.symbol_panel_open = true;
                }
                Err(e) => eprintln!("{:?}", e),
            }
        }
    }

    /// Unload an object file, dropping any caller search that was run
    /// against it (or re-pointing it if its object shifted down).
    fn remove_object(&mut self, key: ObjectKey) {
        self.app.remove_object(key);
        self.callers = self.callers.take().and_then(|search| match search.obj {
            obj if obj == key => None,
            _ => Some(search),
        });
    }

    /// Show `addr` in the disassembly panel: select the function containing
    /// it and queue a scroll to the instruction itself.
    fn reveal(&mut self, obj: ObjectKey, addr: u64) {
        let Some(func) = self
            .app
            .objects
            .get(obj)
            .and_then(|o| o.disasm.function_containing(addr))
        else {
            return;
        };

        self.app.active = Some(Location {
            obj,
            addr: func.addr,
        });
        self.scroll_to = Some(addr);
    }

    /// Run a "who calls this?" query and open the results panel.
    fn find_callers(&mut self, obj: ObjectKey, target: u64) {
        let Some(object) = self.app.objects.get(obj) else {
            return;
        };

        self.callers = Some(CallerSearch::run(obj, object, target));
    }

    fn handle_fullscreen(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
            self.fullscreen = !self.fullscreen;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
        }
    }

    fn handle_drag_and_drop(&mut self, ctx: &egui::Context) {
        let dropped: Vec<_> = ctx.input(|i| {
            // Log files currently hovering over the window.
            for file in &i.raw.hovered_files {
                println!("hovering: {:?}", file.path);
            }

            // Collect files dropped this frame.
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path.clone().unwrap())
                .collect()
        });

        for path in dropped {
            //TODO: check for duplicates, probably inside open_file
            self.open_file(&path);
        }
    }

    fn show_top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar")
            .show_separator_line(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // Left dot — toggles breakpoint panel
                    if ui.button(RichText::new("●").size(24.)).clicked() {
                        self.break_panel_open = !self.break_panel_open;
                    }

                    // Left hamburger — toggles symbol panel
                    if ui.button(RichText::new("☰").size(24.)).clicked() {
                        self.symbol_panel_open = !self.symbol_panel_open;
                    }

                    // Save project
                    if ui.button(RichText::new("💾").size(24.)).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Project", &["yaml", "yml"])
                            .set_file_name("project.yaml")
                            .save_file()
                        {
                            if let Err(e) = self.app.save_to_file(&path) {
                                // TODO: surface this in the UI instead of stderr
                                eprintln!("failed to save project: {e:?}");
                            }
                        }
                    }

                    // Load project
                    if ui.button(RichText::new("📂").size(24.)).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Project", &["yaml", "yml"])
                            .pick_file()
                        {
                            match App::load_from_file(&path) {
                                Ok(app) => self.app = app,
                                Err(e) => eprintln!("failed to load project: {e:?}"),
                            }
                        }
                    }

                    if let Some(file) = self.app.get_active_obj_name()
                        && let Some(sym) = self.app.get_active_sym_name()
                    {
                        ui.horizontal(|ui| {
                            ui.label(file);
                            ui.label(RichText::new(">").weak());
                            ui.label(sym);
                        });
                    } else {
                        ui.label("Nothing selected");
                    };

                    ui.separator();

                    //TODO: menu_button and menu_button_image exist and are likely very useful.
                    // Right hamburger — toggles trace panel
                    if self.app.trace.is_some() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(RichText::new("☰").size(24.)).clicked() {
                                self.trace_panel_open = !self.trace_panel_open;
                            }
                        });
                    }
                });
            });
    }
}

impl eframe::App for Ui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        catppuccin_egui::set_theme(&ctx, THEME);

        self.handle_fullscreen(ctx);
        self.handle_drag_and_drop(ctx);
        self.show_top_bar(ctx);

        break_panel::break_panel(ctx, self);
        sym_panel::sym_panel(ctx, self);
        trace_panel::trace_panel(ctx, self);
        disasm_panel::disasm_panel(ctx, self);
        callers_panel::callers_panel(ctx, self);
    }
}

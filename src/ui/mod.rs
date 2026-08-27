use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use eframe::NativeOptions;
use egui::{FontData, FontDefinitions, FontFamily, Key::N, RichText};
use fuzzy_matcher::skim::SkimMatcherV2;

use crate::{App, ObjectFile, disasm::DisasmBinary, trace_file::TraceFile};

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
}

impl Ui {
    pub fn new() -> Self {
        Ui {
            app: App {
                objects: Vec::new(),
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
                    let name = path.file_stem().unwrap().to_string_lossy().into_owned();
                    self.app.objects.push(ObjectFile {
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
                    // Left dot — toggles symbol panel
                    if ui.button(RichText::new("●").size(24.)).clicked() {
                        self.break_panel_open = !self.break_panel_open;
                    }

                    // Left hamburger — toggles symbol panel
                    if ui.button(RichText::new("☰").size(24.)).clicked() {
                        self.symbol_panel_open = !self.symbol_panel_open;
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

        egui::SidePanel::left("breakpoints")
            .show_separator_line(true)
            .resizable(true)
            .default_width(400.0)
            .show_animated(ctx, self.break_panel_open, |ui| {
                ui.label("Breakpoints");
                for obj in &mut self.app.objects {
                    ui.label(&obj.name);
                    for bp in &obj.breakpoints {
                        let matches: Vec<_> =
                            obj.disasm.functions().filter(|f| f.contains(*bp)).collect();

                        if !matches.is_empty() {
                            ui.label(matches[0].name);
                        }
                    }
                }
            });

        sym_panel::sym_panel(ctx, self);
        trace_panel::trace_panel(ctx, self);
        disasm_panel::disasm_panel(ctx, self);
    }
}

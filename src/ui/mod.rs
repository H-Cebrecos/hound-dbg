use std::path::Path;

use eframe::NativeOptions;
use egui::{FontData, FontDefinitions, FontFamily, RichText};

use crate::{App, ObjectFile, disasm::DisasmBinary};

mod disasm_panel;
mod sym_panel;
mod trace_panel;

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
                    FontData::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/assets/MononokiNerdFontMono-Regular.ttf"
                    )))
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

        sym_panel::sym_panel(&ctx, self);
        trace_panel::trace_panel(&ctx, self);
    }
}

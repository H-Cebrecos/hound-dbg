use egui::{Context, RichText};

pub fn trace_panel(ctx: &Context, ui_app: &mut super::Ui) {
    if let Some(trace) = &ui_app.app.trace {
        egui::SidePanel::right("trace_panel")
    .show_separator_line(false)
    .resizable(false)
    .default_width(400.0)
    .show_animated(ctx, ui_app.trace_panel_open, |ui| {
        let trace_name = trace.path().file_stem().and_then(|s| s.to_str()).unwrap_or("Error parsing file name");
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(RichText::new(trace_name).strong());
            ui.label(RichText::new("·").weak());
            ui.label(RichText::new(format!("{} events", trace.event_count())).weak());
        });

        ui.horizontal(|ui| {
            for src in trace.sources(){
                if let Some(active) = ui_app.source_active.get_mut(&src.id) {
                    ui.checkbox(active, &src.name);
                }
            }
        });

        ui.separator();

               egui::ScrollArea::vertical()
                   .stick_to_bottom(true)
                   .show(ui, |ui| {
                       ui.style_mut().override_text_style = Some(egui::TextStyle::Monospace);


                       ui.label(
                           RichText::new("#0:MEMWRITE_1::0xfd7630b2a2ef6071")
                               .monospace()
                               .color(super::THEME.blue),
                       );

                       ui.label(
                           RichText::new("#0:OVERFLOW::                                      @ 3426877816493824232")
                               .monospace()
                               .color(super::THEME.blue),
                       );

                       ui.label(
                           RichText::new("#1:DAQ_COUNTER:0xa61dc1b0a5465bd3:0x191cb6         @ 11059482132507134706")
                               .monospace()
                               .color(super::THEME.green),
                       );

                       ui.label(
                           RichText::new("#2:MEMREAD_1:0xd885b9d042c5f5bf:0x7f6b05ab76afa832 @ 1079037894117179173")
                               .monospace()
                               .color(super::THEME.yellow),
                       );

                       ui.label(
                           RichText::new("#3:BRANCH_TAKEN:0x77167bf3be13f027:0x88c5bacb2698ccc0 @ 6063295116133120025")
                               .monospace()
                               .color(super::THEME.mauve),
                       );
                       // ...
                   });

    });
    }
}

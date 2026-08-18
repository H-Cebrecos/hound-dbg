use egui::{Context, RichText};

pub fn trace_panel(ctx: &Context, ui_app: &mut super::Ui) {
    egui::SidePanel::right("trace_panel")
    .show_separator_line(false)
    .resizable(false)
    .default_width(400.0)
    .show_animated(ctx, ui_app.trace_panel_open, |ui| {
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
                               .color(super::THEME.subtext0),
                       );

                       ui.label(
                           RichText::new(r#"META:#0="CPU0",#1="CPU1",#2="CPU2",#3="CPU3""#)
                               .monospace()
                               .color(super::THEME.subtext0),
                       );

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

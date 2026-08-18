mod ui;
use ui::Ui;

use crate::disasm::DisasmBinary;

mod disasm;

struct ObjectFile {
    name: String,
    disasm: DisasmBinary,
}

fn truncate_middle(s: &str, max: usize) -> String {
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

type ObjectIndex = usize;

struct App {
    // Note: the disassembler is part of the object, as we technically can have mixed architecture systems e.g. ARM32 coexisting with ARM64.
    objects: Vec<ObjectFile>,

    active_sym: Option<u64>,
    active_file: Option<ObjectIndex>, //TODO: these should likely be refs.
}

impl App {
    pub fn get_active_sym_name(&self) -> Option<&str> {
        let file_idx = self.active_file?;
        let addr = self.active_sym?;
        let func = self.objects.get(file_idx)?.disasm.function_at_addr(addr)?;
        Some(func.name)
    }

    pub fn get_active_obj_name(&self) -> Option<&str> {
        let file_idx = self.active_file?;
        Some(&self.objects.get(file_idx)?.name)
    }
}

fn main() -> anyhow::Result<()> {
    Ui::new().run();

    Ok(())
}

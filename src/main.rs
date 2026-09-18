mod ui;
use std::fs::File;

use ui::Ui;

use crate::{disasm::DisasmBinary, trace_file::TraceFile};

mod disasm;
mod trace_file;

struct ObjectFile {
    name: String,
    disasm: DisasmBinary,
    pub breakpoints: std::collections::HashSet<u64>,
}

type ObjectIndex = usize;
/// Which function is currently selected for display in the disassembly panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Selection {
    obj: ObjectIndex,
    addr: u64,
}

struct App {
    // Note: the disassembler is part of the object, as we technically can
    // have mixed architecture systems e.g. ARM32 coexisting with ARM64.
    objects: Vec<ObjectFile>,
    active: Option<Selection>,
    trace: Option<TraceFile>,
}

impl App {
    /// Drop a loaded object file, keeping [`App::active`] pointing at the
    /// same function it did before — objects are addressed by position, so
    /// every selection after `idx` shifts down by one, and a selection
    /// *into* the removed object is cleared.
    pub fn remove_object(&mut self, idx: ObjectIndex) {
        if idx >= self.objects.len() {
            return;
        }

        self.objects.remove(idx);

        self.active = self.active.and_then(|sel| match sel.obj {
            obj if obj == idx => None,
            obj if obj > idx => Some(Selection {
                obj: obj - 1,
                ..sel
            }),
            _ => Some(sel),
        });
    }

    pub fn get_active_sym_name(&self) -> Option<&str> {
        let file_idx = self.active?.obj;
        let addr = self.active?.addr;
        let func = self.objects.get(file_idx)?.disasm.function_at_addr(addr)?;
        Some(func.name)
    }

    pub fn get_active_obj_name(&self) -> Option<&str> {
        let file_idx = self.active?.obj;
        Some(&self.objects.get(file_idx)?.name)
    }
}

fn main() -> anyhow::Result<()> {
    Ui::new().run();

    Ok(())
}

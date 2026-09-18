mod disasm;
mod trace_file;
mod ui;

use crate::{disasm::DisasmBinary, trace_file::TraceFile};
use slotmap::{SlotMap, new_key_type};
use ui::Ui;

fn main() -> anyhow::Result<()> {
    Ui::new().run();

    Ok(())
}

/// Application runtime state
///
/// This struct contains the application state that its independent of the GUI logic,
/// The idea is that once "projects" are supported serializing this struct should
/// provide all the data necessary information to recreate the current state.
struct App {
    /// Object files (Executables) loaded for analysis
    ///
    /// Multiple objects are supported as it is possible that a trace spans across multiple
    /// different objects, for example the most common case is tracing a bootloader loading
    /// an application, or tracing an OS and its programs.
    ///
    /// A SlotMap is used to allow deletions with stable key references to ensure there is
    /// no data corruption on [`Location`]
    objects: SlotMap<ObjectKey, ObjectFile>,

    /// Currently selected or highlighted location
    active: Option<Location>, //TODO: move this into gui

    /// CTXP trace file used for analysis
    trace: Option<TraceFile>,
}

new_key_type! { pub struct ObjectKey; }
struct ObjectFile {
    /// Path this file was loaded from
    // path: PathBuf, TODO
    name: String,
    // Note: the disassembler is part of the object, as we technically can
    // have mixed architecture systems e.g. ARM32 coexisting with ARM64.
    disasm: DisasmBinary,
    pub breakpoints: std::collections::HashSet<u64>,
}

/// Represents a specific address of an object file (usually a symbol/function)
///
/// Used for various things like selection, and "links" across pannels and elements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    obj: ObjectKey,
    addr: u64,
}

impl App {
    /// Drop a loaded object file
    ///
    /// objects are addressed by position, so locations may need to be updated, see [`Location`]
    pub fn remove_object(&mut self, key: ObjectKey) {
        if !self.objects.contains_key(key) {
            return;
        }

        self.objects.remove(key);
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

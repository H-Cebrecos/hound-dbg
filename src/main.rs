mod disasm;
mod trace_file;
mod ui;

use crate::{disasm::DisasmBinary, trace_file::TraceFile};
use serde::{Deserialize, Serialize};
use slotmap::{SlotMap, new_key_type};
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
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
    active: Option<Location>,

    /// CTXP trace file used for analysis
    trace: Option<TraceFile>,
}

new_key_type! { pub struct ObjectKey; }
struct ObjectFile {
    /// Path this file was loaded from
    path: PathBuf,

    /// Object name
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

    /// Save the current project to `path` as YAML.
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let project = self.to_project();
        let yaml = serde_yaml::to_string(&project)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }

    /// Load a project from `path`.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let yaml = std::fs::read_to_string(path)?;
        let project: ProjectFile = serde_yaml::from_str(&yaml)?;
        Self::from_project(project)
    }

    /// Produce the serializable project representation of the current state.
    fn to_project(&self) -> ProjectFile {
        ProjectFile {
            objects: self
                .objects
                .values()
                .map(|obj| ProjectObject {
                    path: obj.path.clone(),
                    breakpoints: obj.breakpoints.clone(),
                })
                .collect(),
            trace: self.trace.as_ref().map(|t| t.path.clone()),
        }
    }

    /// Rebuild an `App` from a saved project: every object and the trace
    /// file are reopened from their stored paths.
    fn from_project(project: ProjectFile) -> anyhow::Result<Self> {
        let mut objects = SlotMap::default();

        for saved in project.objects {
            let disasm = DisasmBinary::load(&saved.path).map_err(|e| {
                anyhow::anyhow!("failed to load object at {}: {e:?}", saved.path.display())
            })?;
            let name = saved
                .path
                .file_stem()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            objects.insert(ObjectFile {
                path: saved.path,
                name,
                disasm,
                breakpoints: saved.breakpoints,
            });
        }

        let trace = project.trace.map(|p| TraceFile::load(&p)).transpose()?;

        Ok(Self {
            objects,
            active: None, // intentionally not restored
            trace,
        })
    }
}

/// On-disk project format. This is the ONLY thing that gets (de)serialized.
#[derive(Serialize, Deserialize)]
struct ProjectFile {
    objects: Vec<ProjectObject>,
    trace: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct ProjectObject {
    path: PathBuf,
    breakpoints: HashSet<u64>,
}

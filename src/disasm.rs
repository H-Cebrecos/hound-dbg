//! Disassembly abstraction layer.
//!
//! Provides architecture-independent instruction decoding over loaded binaries.
//!

// ============================================================================
// Public types
// ============================================================================

use std::{fs, ops::Range};

use addr2line::fallible_iterator::FallibleIterator;
use capstone::{
    Capstone, Insn,
    arch::{
        self, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode,
        arm64::Arm64InsnGroup::*, riscv::RiscVInsnGroup::*,
    },
};

use object::{Architecture, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

/// High-level classification of an instruction's control-flow behavior.
#[derive(Debug, Clone, Copy)]
pub enum InstrKind {
    /// Conditional branch with a statically known target.
    CondBranch(u64),

    /// Unconditional jump with a statically known target.
    DirectJump(u64),

    /// Unconditional jump whose target requires runtime resolution.
    IndirectJump,

    /// Direct call with a statically known target.
    DirectCall(u64),

    /// Call whose target requires runtime resolution.
    IndirectCall,

    /// Return from current function.
    Return,

    /// Any instruction that does not affect control flow.
    Other,
}

/// Architecture-independent representation of a single decoded instruction.
#[derive(Debug, Clone)]
pub struct DisasmInstr {
    /// Address of the instruction within the binary's address space.
    pub addr: u64,

    /// Control-flow classification, used by CFG reconstruction.
    pub kind: InstrKind,

    /// Human-readable disassembly text, for display purposes.
    pub text: String,

    /// Raw instruction bytes, variable width.
    pub bytes: Vec<u8>,
}

impl DisasmInstr {
    pub fn is_control_flow(&self) -> bool {
        match &self.kind {
            InstrKind::Other => false,
            _ => true,
        }
    }
}

/// Decoded instruction sequence for a single symbol.
pub struct DisasmFunction<'a> {
    /// Symbol name.
    pub name: &'a str, // borrows from the metadata vec

    /// Entry point address.
    pub addr: u64,

    pub size: u64,

    instructions: &'a [DisasmInstr],
}

impl DisasmFunction<'_> {
    /// Returns an iterator over the instructions in this function.
    pub fn instructions(&self) -> impl Iterator<Item = &DisasmInstr> {
        self.instructions.iter()
    }

    /// Returns the last address that is part of the function
    pub fn end_addr(&self) -> u64 {
        self.addr + self.size
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr <= self.end_addr()
    }
}

impl<'a> IntoIterator for &'a DisasmFunction<'a> {
    type Item = &'a DisasmInstr;
    type IntoIter = std::slice::Iter<'a, DisasmInstr>;

    fn into_iter(self) -> Self::IntoIter {
        self.instructions.iter()
    }
}

/// One logical frame at an address — either the sole real frame, or one
/// level of an inlined call chain (innermost first).
pub struct InlineFrame {
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

/// A loaded binary with its decoded instruction stream.
///
/// Exposes two query surfaces:
/// - Symbol-driven, for the UI (function browser, symbol finder).
/// - Address-driven, for trace replay.
pub struct DisasmBinary {
    // flat sorted index over all instructions for O(log n) address lookup
    index: Vec<DisasmInstr>,

    /// Symbol metadata. Each entry references a contiguous slice of `index`.
    /// Stored as (name, addr, range_in_index) to avoid self-referential structs.
    functions: Vec<(String, u64, Range<usize>)>,

    /// Source program lines
    debug_info: Option<addr2line::Loader>,
}

impl DisasmBinary {
    /// Load and decode a binary from the given path.
    pub fn load(path: &std::path::Path) -> Result<Self, DisasmError> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) => return Err(DisasmError::IoError(err)),
        };

        let obj =
            object::File::parse(&*data).map_err(|e| DisasmError::ParseError(e.to_string()))?;

        let mut sections: Vec<_> = obj
            .sections()
            .filter(|sec| sec.kind() == SectionKind::Text)
            .collect();

        sections.sort_by_key(|sec| sec.address());

        let engine = CapstoneBackend::new(obj.architecture());
        let mut index: Vec<DisasmInstr> = Vec::new();
        for sec in &sections {
            let data = sec.data().map_err(|e| {
                DisasmError::BackendError(format!(
                    "failed to read section {:?} data: {e}",
                    sec.name().unwrap_or("<unnamed>")
                ))
            })?;

            let instructions = engine.decode(data, sec.address()).map_err(|e| {
                DisasmError::BackendError(format!(
                    "failed to decode section {:?} ({:#x}..{:#x}, {} bytes): {:?}",
                    sec.name().unwrap_or("<unnamed>"),
                    sec.address(),
                    sec.address() + data.len() as u64,
                    data.len(),
                    e,
                ))
            })?;

            index.extend(instructions);
        }

        debug_assert!(
            index.windows(2).all(|w| w[0].addr <= w[1].addr),
            "index is not sorted by address"
        );

        let debug_info = match addr2line::Loader::new(path) {
            Ok(loader) => Some(loader),
            Err(e) => {
                eprintln!("failed to load debug info for {}: {e}", path.display());
                None
            }
        };

        // First pass: collect all function-symbol addresses so we can use them
        // as boundaries when a symbol is missing an explicit `.size`.
        let mut symbol_addrs: Vec<u64> = obj
            .symbols()
            .filter(|sym| sym.is_definition() && symbol_looks_like_function(&obj, sym))
            .map(|sym| sym.address())
            .collect();
        symbol_addrs.sort_unstable();
        symbol_addrs.dedup();

        let mut functions = Vec::new();

        for sym in obj.symbols() {
            if !sym.is_definition() {
                continue;
            }

            // Accept symbols explicitly typed as functions, *or* untyped symbols
            // that live in a text section as hand-written assembly frequently
            // omits `.type`/`.size` directives that compilers always emit.
            if !symbol_looks_like_function(&obj, &sym) {
                continue;
            }

            let Ok(name) = sym.name() else {
                eprintln!("symbol at {:#x} has unreadable name", sym.address());
                continue;
            };

            let name = demangle(name);

            if is_noise_symbol(&name) {
                continue;
            }

            let addr = sym.address();

            // Size may be missing (no `.size` directive). Fall back to computing
            // it from the next known symbol boundary rather than dropping the
            // symbol outright.
            let size = if sym.size() != 0 {
                sym.size()
            } else {
                let estimated = {
                    // Estimate a symbol's size when no explicit `.size` directive was given,
                    // by finding the address of the next known symbol after it (or the end
                    // of its containing section, if it's the last symbol in that section).
                    let section_end = sections
                        .iter()
                        .find(|s| addr >= s.address() && addr < s.address() + s.size())
                        .map(|s| s.address() + s.size());

                    let idx = symbol_addrs.partition_point(|&a| a <= addr);
                    let next_symbol = symbol_addrs.get(idx).copied();

                    match (next_symbol, section_end) {
                        (Some(n), Some(e)) => n.min(e) - addr,
                        (Some(n), None) => n - addr,
                        (None, Some(e)) => e - addr,
                        (None, None) => 0,
                    }
                };

                estimated
            };

            if size == 0 {
                eprintln!("symbol {name} at {addr:#x} has no determinable size, skipping");
                continue;
            }

            let start_idx = index
                .binary_search_by_key(&addr, |i| i.addr)
                .unwrap_or_else(|insert_pos| insert_pos);

            let end_addr = addr + size;
            let end_idx = index
                .binary_search_by_key(&end_addr, |i| i.addr)
                .unwrap_or_else(|insert_pos| insert_pos);

            debug_assert!(
                start_idx >= index.len() || index[start_idx].addr == addr,
                "symbol {name} at {addr:#x} doesn't land on an instruction boundary"
            );

            functions.push((name, addr, start_idx..end_idx));
        }

        Ok(Self {
            index,
            functions,
            debug_info,
        })
    }

    /// Look up a function by symbol name.
    pub fn function_by_name(&self, name: &str) -> Option<DisasmFunction<'_>> {
        let (fn_name, addr, range) = self.functions.iter().find(|(n, _, _)| n == name)?;
        Some(DisasmFunction {
            name: fn_name,
            addr: *addr,
            size: self.function_size(range),
            instructions: &self.index[range.clone()],
        })
    }

    /// Look up a function by its entry point address.
    pub fn function_at_addr(&self, addr: u64) -> Option<DisasmFunction<'_>> {
        let (fn_name, fn_addr, range) = self.functions.iter().find(|(_, a, _)| *a == addr)?;
        Some(DisasmFunction {
            name: fn_name,
            addr: *fn_addr,
            size: self.function_size(range),
            instructions: &self.index[range.clone()],
        })
    }

    /// Iterate over all decoded functions.
    pub fn functions(&self) -> impl Iterator<Item = DisasmFunction<'_>> {
        self.functions
            .iter()
            .map(|(name, addr, range)| DisasmFunction {
                name,
                addr: *addr,
                size: self.function_size(range),
                instructions: &self.index[range.clone()],
            })
    }

    /// Return the instruction at exactly the given address, if any.
    pub fn instruction_at(&self, addr: u64) -> Option<&DisasmInstr> {
        let idx = self.index.binary_search_by_key(&addr, |i| i.addr).ok()?;
        self.index.get(idx)
    }

    /// Return all instructions whose address falls within the given range.
    ///
    /// The range is expected to correspond to at most one basic block —
    /// no taken branches will appear within it.
    pub fn instructions_in(&self, range: Range<u64>) -> impl Iterator<Item = &DisasmInstr> {
        let start = self
            .index
            .binary_search_by_key(&range.start, |i| i.addr)
            .unwrap_or_else(|p| p);
        let end = self
            .index
            .binary_search_by_key(&range.end, |i| i.addr)
            .unwrap_or_else(|p| p);
        self.index[start..end].iter()
    }

    /// Byte size of a function, computed from where its instruction range
    /// ends in `index` — either the next instruction's address, or (for
    /// the last function in a section) the address just past the final
    /// instruction's own bytes.
    fn function_size(&self, range: &Range<usize>) -> u64 {
        if range.is_empty() {
            return 0;
        }
        let start_addr = self.index[range.start].addr;
        let end_addr = match self.index.get(range.end) {
            Some(next) => next.addr,
            None => {
                let last = &self.index[range.end - 1];
                last.addr + last.bytes.len() as u64
            }
        };
        end_addr - start_addr
    }

    /// Innermost source location for an address, ignoring any inlining
    /// chain. `None` if no debug info is present or the address isn't covered.
    pub fn line_for_addr(&self, addr: u64) -> Option<(String, u32, u32)> {
        let loader = self.debug_info.as_ref()?;
        let loc = loader.find_location(addr).ok()??;
        Some((
            loc.file.unwrap_or("<unknown>").to_string(),
            loc.line.unwrap_or(0),
            loc.column.unwrap_or(0),
        ))
    }

    /// Full inlined call chain for an address, innermost frame first.
    /// Empty if no debug info; a single entry if the address isn't inlined.
    pub fn frames_for_addr(&self, addr: u64) -> Vec<InlineFrame> {
        let Some(loader) = self.debug_info.as_ref() else {
            return Vec::new();
        };

        let Ok(frame_iter) = loader.find_frames(addr) else {
            return Vec::new();
        };
        let Ok(frames) = frame_iter.collect::<Vec<_>>() else {
            return Vec::new();
        };

        frames
            .into_iter()
            .map(|f| InlineFrame {
                function: f
                    .function
                    .as_ref()
                    .and_then(|n| n.demangle().ok().map(|s| s.into_owned()))
                    .unwrap_or_else(|| "<unknown>".to_string()),
                file: f.location.as_ref().and_then(|l| l.file).map(str::to_string),
                line: f.location.as_ref().and_then(|l| l.line),
                column: f.location.as_ref().and_then(|l| l.column),
            })
            .collect()
    }

    /// Attempts to resolve the target of an indirect branch by performing
    /// abstract interpretation over the instructions leading up to it.
    /// Returns None if the target cannot be statically determined.
    pub fn resolve_indirect(&self, context: &[DisasmInstr]) -> Option<u64> {
        todo!()

        // is this made redundant by the next address? we need to keep one or the other, this one has actual context.
    }
}

/// Whether a symbol should be treated as a function definition: either
/// explicitly typed as such, or untyped but living in a text section
/// (common in hand-written assembly that omits `.type` directives).
fn symbol_looks_like_function(obj: &object::File, sym: &object::Symbol) -> bool {
    let in_text_section = sym
        .section_index()
        .and_then(|idx| obj.section_by_index(idx).ok())
        .map(|sec| sec.kind() == SectionKind::Text)
        .unwrap_or(false);

    match sym.kind() {
        SymbolKind::Text => true,
        SymbolKind::Unknown if in_text_section => true,
        _ => false,
    }
}

// ============================================================================
// Internal backend trait
// ============================================================================

/// Decoding backend. Sealed — nothing outside this module interacts with it.
trait DisasmBackend {
    fn decode(&self, bytes: &[u8], base_addr: u64) -> Result<Vec<DisasmInstr>, DisasmError>;
}

struct CapstoneBackend {
    engine: Capstone,
    arch: Architecture,
}

impl CapstoneBackend {
    pub fn new(arch: Architecture) -> Self {
        let mut capstone = match arch {
            Architecture::Riscv32 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV32)
                .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
                .detail(true)
                .build()
                .unwrap(),

            Architecture::Riscv64 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV64)
                .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
                .detail(true)
                .build()
                .unwrap(),

            Architecture::Arm => todo!(),
            Architecture::Aarch64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .endian(capstone::Endian::Little) //TODO: support big endian
                .detail(true)
                .build()
                .unwrap(),

            Architecture::Wasm32 => todo!(),
            Architecture::Wasm64 => todo!(),

            _ => todo!("Unsuported architecture {:?}", arch),
        };

        capstone.set_skipdata(true).unwrap();

        CapstoneBackend {
            arch,
            engine: capstone,
        }
    }

    fn classify_instr(&self, insn: &Insn) -> Result<InstrKind, DisasmError> {
        match self.arch {
            Architecture::Riscv32 | Architecture::Riscv64 => {
                let detail = match self.engine.insn_detail(insn) {
                    Ok(d) => d,
                    Err(_) => return Ok(InstrKind::Other),
                };

                let groups = detail.groups();

                let mut has_ret = false;
                let mut has_branch = false;
                let mut has_jump = false;

                for g in groups {
                    match g.0 as u32 {
                        RISCV_GRP_RET | RISCV_GRP_IRET => has_ret = true,
                        RISCV_GRP_BRANCH_RELATIVE => has_branch = true,
                        RISCV_GRP_JUMP | RISCV_GRP_CALL => has_jump = true,
                        _ => {}
                    }
                }

                if has_ret {
                    return Ok(InstrKind::Return);
                }

                if has_branch || has_jump {
                    let imm = detail
                        .arch_detail()
                        .operands()
                        .iter()
                        .find_map(|op| match op {
                            arch::ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Imm(
                                imm,
                            )) => Some(*imm),
                            _ => None,
                        });

                    Ok(match (has_branch, imm) {
                        (true, Some(imm)) => {
                            InstrKind::CondBranch(insn.address().wrapping_add(imm as u64))
                        }
                        (false, Some(imm)) => {
                            InstrKind::DirectJump(insn.address().wrapping_add(imm as u64))
                        }
                        (_, None) => InstrKind::IndirectJump,
                    })
                } else {
                    Ok(InstrKind::Other)
                }
            }
            Architecture::Aarch64 => {
                let detail = match self.engine.insn_detail(insn) {
                    Ok(d) => d,
                    Err(_) => return Ok(InstrKind::Other),
                };

                let groups = detail.groups();

                let mut has_ret = false;
                let mut has_branch = false;
                let mut has_jump = false;

                for g in groups {
                    match g.0 as u32 {
                        ARM64_GRP_RET => has_ret = true,
                        ARM64_GRP_BRANCH_RELATIVE => has_branch = true,
                        ARM64_GRP_JUMP | ARM64_GRP_CALL => has_jump = true,
                        _ => {}
                    }
                }
                if has_ret {
                    return Ok(InstrKind::Return);
                }

                if has_branch || has_jump {
                    let imm = detail
                        .arch_detail()
                        .operands()
                        .iter()
                        .find_map(|op| match op {
                            arch::ArchOperand::Arm64Operand(op) => match op.op_type {
                                arch::arm64::Arm64OperandType::Imm(imm) => Some(imm),
                                _ => None,
                            },
                            _ => None,
                        });

                    Ok(match (has_branch, imm) {
                        (true, Some(imm)) => {
                            InstrKind::CondBranch(insn.address().wrapping_add(imm as u64))
                        }
                        (false, Some(imm)) => {
                            InstrKind::DirectJump(insn.address().wrapping_add(imm as u64))
                        }
                        (_, None) => InstrKind::IndirectJump,
                    })
                } else {
                    Ok(InstrKind::Other)
                }
            }
            arch => Err(DisasmError::UnsupportedArchitecture(arch)),
        }
    }
}

impl DisasmBackend for CapstoneBackend {
    fn decode(&self, bytes: &[u8], base_addr: u64) -> Result<Vec<DisasmInstr>, DisasmError> {
        let raw_instructions = self
            .engine
            .disasm_all(bytes, base_addr)
            .map_err(|e| DisasmError::BackendError(e.to_string()))?;

        raw_instructions
            .iter()
            .map(|i| {
                let kind = self.classify_instr(i)?;

                let bytes = i.bytes().to_vec();

                Ok(DisasmInstr {
                    addr: i.address(),
                    kind,
                    text: i.to_string(),
                    bytes,
                })
            })
            .collect()
    }
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug)]
pub enum DisasmError {
    /// The file could not be read or parsed.
    IoError(std::io::Error),

    /// The object file format is not supported.
    ParseError(String),

    /// The target architecture is not supported.
    UnsupportedArchitecture(Architecture),

    /// The disassembler backend returned an error.
    BackendError(String),
}

// ============================================================================
//  Helpers
// ============================================================================

fn demangle(name: &str) -> String {
    if let Ok(sym) = rustc_demangle::try_demangle(name) {
        return sym.to_string();
    }

    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(out) = sym.demangle() {
            return out;
        }
    }

    name.to_string()
}

fn is_noise_symbol(name: &str) -> bool {
    name.starts_with(".L")
        || name.starts_with("Ltmp")
        || name.starts_with("LBB")
        || name.starts_with("$x")
        || name.starts_with("$d")
        || name.starts_with("$t")
        || name == "$a"
        || name.is_empty()
}

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

impl InstrKind {
    /// Statically known destination of a direct control-flow instruction.
    ///
    /// `None` for instructions that don't branch, or whose destination only
    /// becomes known at runtime.
    pub fn target(&self) -> Option<u64> {
        match *self {
            InstrKind::CondBranch(addr)
            | InstrKind::DirectJump(addr)
            | InstrKind::DirectCall(addr) => Some(addr),
            InstrKind::IndirectJump
            | InstrKind::IndirectCall
            | InstrKind::Return
            | InstrKind::Other => None,
        }
    }

    /// Whether this instruction establishes a new call frame, regardless of
    /// whether its target is statically known.
    pub fn is_call(&self) -> bool {
        matches!(self, InstrKind::DirectCall(_) | InstrKind::IndirectCall)
    }
}

impl DisasmInstr {
    pub fn is_control_flow(&self) -> bool {
        match &self.kind {
            InstrKind::Other => false,
            _ => true,
        }
    }
}

/// One instruction that transfers control to a given function.
///
/// Produced by [`DisasmBinary::callers_of`]; addresses index back into the
/// same binary the query was made against.
#[derive(Debug, Clone, Copy)]
pub struct CallSite {
    /// Entry address of the function the call was found in.
    pub caller_addr: u64,

    /// Address of the calling instruction itself.
    pub site_addr: u64,

    /// True when control is transferred by a plain branch to the target's
    /// entry point (a tail call) rather than by a linking call instruction.
    pub tail: bool,
}

/// One raw symbol observed at a given address, before canonical-name
/// resolution. Carries just enough concreteness info to rank it.
struct SymbolAlias {
    name: String,
    /// True if the symbol's kind was explicitly `SymbolKind::Text` (compiler-
    /// declared), false if it was accepted only because it sits in a text
    /// section with `SymbolKind::Unknown` (assembly without `.type`).
    explicit_type: bool,
    /// `Some(size)` if the symbol carried a nonzero `.size`; `None` if it
    /// was missing (assembly without `.size`) and would need inference.
    explicit_size: Option<u64>,
}

/// Rank used to pick the canonical alias at an address — lower sorts first
/// and is preferred as canonical. Primary criteria are how much concrete
/// data the compiler/assembler actually gave us (explicit type, explicit
/// size); name shape is only a tiebreak among equally concrete aliases.
fn alias_rank(alias: &SymbolAlias) -> (bool, bool, usize, bool, usize, &str) {
    let (leading_underscores, is_versioned, len) = name_shape(&alias.name);
    (
        !alias.explicit_type,          // explicitly typed sorts before inferred
        alias.explicit_size.is_none(), // explicit size sorts before missing
        leading_underscores,
        is_versioned,
        len,
        alias.name.as_str(), // final tiebreak: deterministic ordering
    )
}

/// Name-shape signal, used only to break ties between equally concrete
/// aliases (e.g. two compiler-declared symbols at the same address).
fn name_shape(name: &str) -> (usize, bool, usize) {
    let leading_underscores = name.chars().take_while(|&c| c == '_').count();
    let is_versioned = name.contains('@');
    (leading_underscores, is_versioned, name.len())
}

/// Decoded instruction sequence for a single symbol.
#[derive(Debug, Clone, Copy)]
pub struct DisasmFunction<'a> {
    /// Canonical display name, the most "normal-looking" of any aliases
    /// sharing this address. See `canonical_name_rank`.
    pub name: &'a str,

    /// All symbol names observed at this address, including `name` itself,
    /// ordered by canonicalness (most canonical first).
    pub aliases: &'a [String],

    /// Entry point address.
    pub addr: u64,

    pub size: u64,

    instructions: &'a [DisasmInstr],
}

//NOTE: this exists to avoid cyclical deps
struct FunctionEntry {
    addr: u64,
    range: Range<usize>,
    /// All names sharing this address, canonical-rank order (names[0] is
    /// the canonical/display name).
    names: Vec<String>,
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
        addr >= self.addr && addr < self.end_addr()
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

    /// One entry per unique address that has at least one function symbol.
    /// `names` holds every alias observed at that address, canonical first.
    functions: Vec<FunctionEntry>,

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

        // First pass: group every function-like symbol by address, preserving
        // per-symbol concreteness (explicit type/size vs. inferred). Multiple
        // symbols legitimately share an address (weak/strong alias pairs,
        // versioned symbols, multiple assembly entry labels) — we keep all of
        // them as searchable aliases rather than dropping any.
        let mut by_addr: std::collections::HashMap<u64, Vec<SymbolAlias>> =
            std::collections::HashMap::new();

        for sym in obj.symbols() {
            if !sym.is_definition() {
                continue;
            }

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

            by_addr.entry(sym.address()).or_default().push(SymbolAlias {
                name,
                explicit_type: sym.kind() == SymbolKind::Text,
                explicit_size: (sym.size() != 0).then_some(sym.size()),
            });
        }

        let mut sorted_addrs: Vec<u64> = by_addr.keys().copied().collect();
        sorted_addrs.sort_unstable();

        let mut functions = Vec::new();

        for &addr in &sorted_addrs {
            let mut aliases = by_addr.remove(&addr).unwrap();

            // Canonical alias = the one backed by the most concrete compiler/
            // assembler-provided data; name shape only breaks ties.
            aliases.sort_by(|a, b| alias_rank(a).cmp(&alias_rank(b)));

            // Prefer size from the most concrete alias that actually has one —
            // aliases are already sorted by concreteness, so the first
            // `explicit_size` we find is the best available. Only fall back to
            // inference (still needed for hand-written assembly with no
            // `.size` on *any* alias at this address) if none had one.
            let size = match aliases.iter().find_map(|a| a.explicit_size) {
                Some(size) => size,
                None => {
                    let estimated = {
                        // Estimate a symbol's size when no explicit `.size` directive was given,
                        // by finding the address of the next known symbol after it (or the end
                        // of its containing section, if it's the last symbol in that section).
                        let section_end = sections
                            .iter()
                            .find(|s| addr >= s.address() && addr < s.address() + s.size())
                            .map(|s| s.address() + s.size());

                        let idx = sorted_addrs.partition_point(|&a| a <= addr);
                        let next_symbol = sorted_addrs.get(idx).copied();

                        match (next_symbol, section_end) {
                            (Some(n), Some(e)) => n.min(e) - addr,
                            (Some(n), None) => n - addr,
                            (None, Some(e)) => e - addr,
                            (None, None) => 0,
                        }
                    };

                    estimated
                }
            };

            if size == 0 {
                eprintln!(
                    "symbol {} at {addr:#x} has no determinable size, skipping",
                    aliases[0].name
                );
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
                "symbol {} at {addr:#x} doesn't land on an instruction boundary",
                aliases[0].name
            );

            functions.push(FunctionEntry {
                addr,
                range: start_idx..end_idx,
                names: aliases.into_iter().map(|a| a.name).collect(),
            });
        }

        Ok(Self {
            index,
            functions,
            debug_info,
        })
    }

    /// Look up a function by any of its symbol names (canonical or alias).
    pub fn function_by_name(&self, name: &str) -> Option<DisasmFunction<'_>> {
        let entry = self
            .functions
            .iter()
            .find(|e| e.names.iter().any(|n| n == name))?;
        Some(self.function_from_entry(entry))
    }

    /// Look up a function by its entry point address.
    pub fn function_at_addr(&self, addr: u64) -> Option<DisasmFunction<'_>> {
        // `functions` is built from a sorted address list, so entry lookup
        // is a binary search rather than a scan.
        let idx = self
            .functions
            .binary_search_by_key(&addr, |e| e.addr)
            .ok()?;
        Some(self.function_from_entry(&self.functions[idx]))
    }

    /// Look up the function whose body covers `addr`, which need not be its
    /// entry point.
    pub fn function_containing(&self, addr: u64) -> Option<DisasmFunction<'_>> {
        let idx = self.functions.partition_point(|e| e.addr <= addr);
        let entry = self.functions.get(idx.checked_sub(1)?)?;
        let func = self.function_from_entry(entry);
        func.contains(addr).then_some(func)
    }

    /// Canonical symbol name of the function that starts exactly at `addr`.
    ///
    /// Deliberately entry-point-only: it answers "is this address a known
    /// symbol?", which is what branch-target resolution needs.
    pub fn symbol_at(&self, addr: u64) -> Option<&str> {
        self.function_at_addr(addr).map(|f| f.name)
    }

    /// Iterate over all decoded functions (one entry per unique address).
    pub fn functions(&self) -> impl Iterator<Item = DisasmFunction<'_>> {
        self.functions
            .iter()
            .map(|entry| self.function_from_entry(entry))
    }

    /// Every instruction in this binary that transfers control to the
    /// function entry at `target`.
    ///
    /// Both linking calls and tail calls (a plain branch from *another*
    /// function into `target`'s entry point) count as call sites; a branch
    /// back to the target's own entry is a loop, not a call, and is skipped.
    pub fn callers_of(&self, target: u64) -> Vec<CallSite> {
        let mut sites = Vec::new();

        for entry in &self.functions {
            for instr in &self.index[entry.range.clone()] {
                if instr.kind.target() != Some(target) {
                    continue;
                }

                let tail = !instr.kind.is_call();
                if tail && entry.addr == target {
                    continue;
                }

                sites.push(CallSite {
                    caller_addr: entry.addr,
                    site_addr: instr.addr,
                    tail,
                });
            }
        }

        sites
    }

    fn function_from_entry<'a>(&'a self, entry: &'a FunctionEntry) -> DisasmFunction<'a> {
        DisasmFunction {
            name: &entry.names[0],
            aliases: &entry.names,
            addr: entry.addr,
            size: self.function_size(&entry.range),
            instructions: &self.index[entry.range.clone()],
        }
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
                let mut has_call = false;

                for g in groups {
                    match g.0 as u32 {
                        RISCV_GRP_RET | RISCV_GRP_IRET => has_ret = true,
                        RISCV_GRP_BRANCH_RELATIVE => has_branch = true,
                        RISCV_GRP_CALL => has_call = true,
                        RISCV_GRP_JUMP => has_jump = true,
                        _ => {}
                    }
                }

                // capstone puts every `jal`/`jalr` in the call group,
                // including the `j`/`jr`/`ret` aliases that discard the
                // return address. The printed mnemonic is what separates
                // them: only the linking forms keep their `jal`/`jalr` name.
                let mnemonic = insn.mnemonic().unwrap_or_default();
                let links = matches!(mnemonic, "jal" | "jalr" | "c.jal" | "c.jalr");

                if has_ret || mnemonic == "ret" {
                    return Ok(InstrKind::Return);
                }

                if has_branch || has_jump || has_call {
                    let imm = detail
                        .arch_detail()
                        .operands()
                        .iter()
                        // The branch target is always the last immediate:
                        // `tbz` and friends carry a bit index first.
                        .filter_map(|op| match op {
                            arch::ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Imm(
                                imm,
                            )) => Some(*imm),
                            _ => None,
                        })
                        .next_back();

                    Ok(branch_kind(
                        has_call && links,
                        has_branch,
                        // RISC-V branch immediates arrive as an offset from
                        // the instruction, unlike AArch64 below.
                        imm.map(|imm| insn.address().wrapping_add(imm as u64)),
                    ))
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
                let mut has_call = false;

                for g in groups {
                    match g.0 as u32 {
                        ARM64_GRP_RET => has_ret = true,
                        ARM64_GRP_BRANCH_RELATIVE => has_branch = true,
                        ARM64_GRP_CALL => has_call = true,
                        ARM64_GRP_JUMP => has_jump = true,
                        _ => {}
                    }
                }
                if has_ret {
                    return Ok(InstrKind::Return);
                }

                if has_branch || has_jump || has_call {
                    let imm = detail
                        .arch_detail()
                        .operands()
                        .iter()
                        // The branch target is always the last immediate:
                        // `tbz` and friends carry a bit index first.
                        .filter_map(|op| match op {
                            arch::ArchOperand::Arm64Operand(op) => match op.op_type {
                                arch::arm64::Arm64OperandType::Imm(imm) => Some(imm),
                                _ => None,
                            },
                            _ => None,
                        })
                        .next_back();

                    Ok(branch_kind(
                        has_call,
                        has_branch,
                        // capstone has already resolved AArch64 branch
                        // immediates against the instruction address.
                        imm.map(|imm| imm as u64),
                    ))
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

/// Classify a branch-like instruction from the groups capstone reported for
/// it, plus its resolved target (if the target was a statically known
/// immediate).
///
/// Calls are checked first: a linking branch (`bl`, `jal ra, …`) carries the
/// relative-branch group too, and being a call is the more specific fact.
fn branch_kind(is_call: bool, is_relative_branch: bool, target: Option<u64>) -> InstrKind {
    match (is_call, is_relative_branch, target) {
        (true, _, Some(target)) => InstrKind::DirectCall(target),
        (true, _, None) => InstrKind::IndirectCall,
        (false, true, Some(target)) => InstrKind::CondBranch(target),
        (false, false, Some(target)) => InstrKind::DirectJump(target),
        (false, _, None) => InstrKind::IndirectJump,
    }
}

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

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
impl DisasmBinary {
    /// Assemble a binary straight from decoded instructions and symbol
    /// bounds, skipping object-file parsing. Test-only: `load` remains the
    /// single production entry point.
    fn from_parts(index: Vec<DisasmInstr>, symbols: &[(u64, u64, &str)]) -> Self {
        let functions = symbols
            .iter()
            .map(|&(addr, end_addr, name)| {
                let idx_of = |a: u64| {
                    index
                        .binary_search_by_key(&a, |i: &DisasmInstr| i.addr)
                        .unwrap_or_else(|insert_pos| insert_pos)
                };

                FunctionEntry {
                    addr,
                    range: idx_of(addr)..idx_of(end_addr),
                    names: vec![name.to_owned()],
                }
            })
            .collect();

        Self {
            index,
            functions,
            debug_info: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a single instruction at `addr` with the backend for `arch`.
    fn decode_one(arch: Architecture, bytes: &[u8], addr: u64) -> DisasmInstr {
        let mut decoded = CapstoneBackend::new(arch)
            .decode(bytes, addr)
            .expect("decode failed");
        assert_eq!(decoded.len(), 1, "expected exactly one instruction");
        decoded.pop().unwrap()
    }

    /// Every branch-target feature (target names, caller lookup, jump
    /// arrows) rests on `InstrKind`'s addresses being absolute, but capstone
    /// doesn't report branch immediates the same way on both backends: it
    /// resolves them against the instruction address on AArch64 and leaves
    /// them relative on RISC-V. Pin that down — a regression here would show
    /// up as targets that silently resolve to no symbol at all.
    #[test]
    fn resolves_branch_immediates_of_both_backends() {
        // bl #+0x10 at 0x1000 — capstone reports 0x1010.
        let aarch64 = decode_one(Architecture::Aarch64, &[0x04, 0x00, 0x00, 0x94], 0x1000);
        assert_eq!(aarch64.kind.target(), Some(0x1010), "{}", aarch64.text);

        // jal ra, 0x10 at 0x1000 — capstone reports 0x10.
        let riscv = decode_one(Architecture::Riscv64, &[0xef, 0x00, 0x00, 0x01], 0x1000);
        assert_eq!(riscv.kind.target(), Some(0x1010), "{}", riscv.text);
    }
    #[test]
    fn classifies_aarch64_control_flow() {
        let at = |bytes: &[u8]| decode_one(Architecture::Aarch64, bytes, 0x1000).kind;

        // bl #+0x10 — a call, even though it is also a relative branch.
        assert!(matches!(
            at(&[0x04, 0x00, 0x00, 0x94]),
            InstrKind::DirectCall(0x1010)
        ));

        // blr x0 — a call whose target is only known at runtime.
        assert!(matches!(
            at(&[0x00, 0x00, 0x3f, 0xd6]),
            InstrKind::IndirectCall
        ));

        // Branches keep their statically known target, and none of them is
        // mistaken for a call.
        for bytes in [
            [0x02, 0x00, 0x00, 0x14], // b    #+0x8
            [0x40, 0x00, 0x00, 0x54], // b.eq #+0x8
            [0x40, 0x00, 0x00, 0xb4], // cbz  x0, #+0x8
            [0x40, 0x00, 0x00, 0x36], // tbz  w0, #0, #+0x8
        ] {
            let kind = at(&bytes);
            // `tbz` carries a bit index before its target, so this also
            // pins down which immediate the target is read from.
            assert_eq!(kind.target(), Some(0x1008), "{kind:?}");
            assert!(!kind.is_call(), "{kind:?}");
        }

        // br x1 — an unresolvable branch.
        assert!(matches!(
            at(&[0x20, 0x00, 0x1f, 0xd6]),
            InstrKind::IndirectJump
        ));

        assert!(matches!(at(&[0xc0, 0x03, 0x5f, 0xd6]), InstrKind::Return));

        // nop — no control flow at all.
        let nop = decode_one(Architecture::Aarch64, &[0x1f, 0x20, 0x03, 0xd5], 0x1000);
        assert!(!nop.is_control_flow());
        assert_eq!(nop.kind.target(), None);
    }

    /// On RISC-V every `jal`/`jalr` lands in capstone's call group, aliases
    /// included, so `j`, `jr` and `ret` have to be told apart from real
    /// calls by mnemonic.
    #[test]
    fn classifies_riscv_control_flow() {
        let at = |bytes: &[u8]| decode_one(Architecture::Riscv64, bytes, 0x1000).kind;

        // jal ra, 0x10 — links, so it is a call.
        assert!(matches!(
            at(&[0xef, 0x00, 0x00, 0x01]),
            InstrKind::DirectCall(0x1010)
        ));

        // j 0x10 (jal zero, 0x10) — same encoding family, but no link.
        assert!(matches!(
            at(&[0x6f, 0x00, 0x00, 0x01]),
            InstrKind::DirectJump(0x1010)
        ));

        // beqz zero, 0x10
        assert!(matches!(
            at(&[0x63, 0x08, 0x00, 0x00]),
            InstrKind::CondBranch(0x1010)
        ));

        // jr zero — an indirect jump, not an indirect call.
        assert!(matches!(
            at(&[0x67, 0x00, 0x00, 0x00]),
            InstrKind::IndirectJump
        ));

        // ret (jalr zero, 0(ra))
        assert!(matches!(at(&[0x67, 0x80, 0x00, 0x00]), InstrKind::Return));
    }

    /// Synthetic three-function binary, laid out back to back the way a
    /// real text section is:
    ///
    /// ```text
    /// 0x1000 caller: call 0x1010 ; call 0x1010 ; branch 0x1000 ; ret
    /// 0x1010 callee: branch 0x1010 ; ret
    /// 0x1018 tail:   jump 0x1010
    /// ```
    fn fixture() -> DisasmBinary {
        let instr = |addr: u64, kind: InstrKind| DisasmInstr {
            addr,
            kind,
            text: String::new(),
            bytes: vec![0; 4],
        };

        let index = vec![
            instr(0x1000, InstrKind::DirectCall(0x1010)),
            instr(0x1004, InstrKind::DirectCall(0x1010)),
            instr(0x1008, InstrKind::CondBranch(0x1000)),
            instr(0x100c, InstrKind::Return),
            instr(0x1010, InstrKind::CondBranch(0x1010)),
            instr(0x1014, InstrKind::Return),
            instr(0x1018, InstrKind::DirectJump(0x1010)),
        ];

        DisasmBinary::from_parts(
            index,
            &[
                (0x1000, 0x1010, "caller"),
                (0x1010, 0x1018, "callee"),
                (0x1018, 0x101c, "tail"),
            ],
        )
    }

    #[test]
    fn resolves_symbols_by_address() {
        let bin = fixture();

        assert_eq!(bin.symbol_at(0x1010), Some("callee"));
        // Entry points only — an address inside a function is not a symbol.
        assert_eq!(bin.symbol_at(0x1014), None);
        assert_eq!(bin.symbol_at(0x2000), None);

        assert_eq!(
            bin.function_containing(0x1014).map(|f| f.name),
            Some("callee")
        );
        assert_eq!(bin.function_containing(0x2000).map(|f| f.name), None);
    }

    #[test]
    fn finds_callers_including_tail_calls() {
        let bin = fixture();

        let named: Vec<_> = bin
            .callers_of(0x1010)
            .iter()
            .map(|s| (bin.symbol_at(s.caller_addr).unwrap(), s.site_addr, s.tail))
            .collect();

        assert_eq!(
            named,
            vec![
                ("caller", 0x1000, false),
                ("caller", 0x1004, false),
                // A branch from another function into the entry point is a
                // tail call; `callee`'s own branch back to 0x1010 is a loop.
                ("tail", 0x1018, true),
            ]
        );

        // `caller`'s branch back to its own entry is not a call either.
        assert!(bin.callers_of(0x1000).is_empty());
    }
}

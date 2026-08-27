//! Binary trace file loading and access.
//!
//! Traces are stored as a sequence of fixed-width (26-byte), independently
//! decodable events. Because decoding is both fixed-width and stateless,
//! any event is directly addressable by `offset = index * EVENT_SIZE` —
//! no index structure or sequential replay is needed for random access.
//! The file is memory-mapped rather than loaded into the process's heap,
//! so memory footprint stays flat regardless of trace size.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use ctxp::Format::Binary;
use fs4::FileExt;
use memmap2::Mmap;

/// A memory-mapped binary trace file.
///
/// Events are fixed-width and independently decodable, so any event index
/// maps directly to a byte offset with no seeking, indexing, or sequential
/// replay required.
pub struct TraceFile {
    /// Path this trace was loaded from, kept for display/error messages.
    path: PathBuf,

    /// Backing memory-mapped file. Never mutated after load.
    mmap: Mmap,

    /// Byte offset within `mmap` where the fixed-width event stream begins
    /// (i.e. right after the header and metadata section).
    events_start: usize,

    /// Number of events in the trace.
    event_count: u64,

    /// Sources declared in the metadata section.
    sources: Vec<ctxp::Source>,

    /// Held for the lifetime of this handle. A shared (read) advisory lock:
    /// coordinates with other well-behaved processes/instances of this
    /// app, but does NOT prevent an uncooperative process from mutating
    /// the file underneath the mmap — advisory locks aren't enforced by
    /// the OS against processes that don't check them.
    _lock_file: File,
}

impl TraceFile {
    /// Byte width of one binary-encoded event.
    pub const EVENT_SIZE: usize = 26;

    /// Memory-map, lock, and parse a binary `.ctxp` trace file.
    pub fn load(path: &Path) -> Result<Self, TraceError> {
        match ctxp::Decoder::detect_format(path) {
            Ok(f) => match f {
                ctxp::Format::Binary => (),
                ctxp::Format::Text => todo!(),
            },
            Err(_) => todo!(),
        }

        let file = File::open(path).map_err(TraceError::IoError)?;

        // Shared lock: readable by other cooperating processes/instances,
        // but signals "please don't write to this while I'm mapped."
        file.lock_shared().map_err(TraceError::LockError)?;

        let dec = ctxp::Decoder::new(&file, Binary).map_err(|e| TraceError::DecodeError(e))?;
        let sources = dec.sources().to_vec();

        let events_start = dec.events_offset as usize;

        let file_len = file.metadata().map_err(TraceError::IoError)?.len() as usize;
        let event_region_len = file_len
            .checked_sub(events_start)
            .ok_or(TraceError::TruncatedFile)?;

        if event_region_len % Self::EVENT_SIZE != 0 {
            return Err(TraceError::MisalignedEventRegion {
                region_len: event_region_len,
                event_size: Self::EVENT_SIZE,
            });
        }
        let event_count = (event_region_len / Self::EVENT_SIZE) as u64;

        // SAFETY: we hold a shared advisory lock on `file` for the
        // lifetime of this `TraceFile`, which deters (but cannot force)
        // concurrent mutation by cooperating processes. The file is
        // treated as read-only and immutable for as long as this handle
        // exists.
        let mmap = unsafe { Mmap::map(&file) }.map_err(TraceError::IoError)?;

        Ok(Self {
            path: path.to_path_buf(),
            mmap,
            events_start,
            event_count,
            sources,
            _lock_file: file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    pub fn sources(&self) -> &[ctxp::Source] {
        &self.sources
    }

    /// Raw bytes for the event at `idx`, or `None` if out of range.
    pub fn event_bytes(&self, idx: u64) -> Option<&[u8; Self::EVENT_SIZE]> {
        if idx >= self.event_count {
            return None;
        }
        let start = self.events_start + idx as usize * Self::EVENT_SIZE;
        self.mmap[start..start + Self::EVENT_SIZE].try_into().ok()
    }

    // /// Decoded event at `idx`, or `None` if out of range.
    // pub fn event(&self, idx: u64) -> Option<Event> {
    //     self.event_bytes(idx).map(decode_event)
    // }

    // /// Iterate over a contiguous range of events, clamped to the trace's
    // /// actual length. Useful for rendering a visible window in the
    // /// scrollable trace view.
    // pub fn events_in(&self, range: std::ops::Range<u64>) -> impl Iterator<Item = Event> + '_ {
    //     let end = range.end.min(self.event_count);
    //     let start = range.start.min(end);
    //     (start..end).map(move |idx| decode_event(self.event_bytes(idx).unwrap()))
    // }
}

impl Drop for TraceFile {
    fn drop(&mut self) {
        // Best-effort: unlock explicitly rather than relying solely on
        // the fd closing (which also releases the lock on all supported
        // platforms, but being explicit documents the intent).
        let _ = FileExt::unlock(&self._lock_file);
    }
}

#[derive(Debug)]
pub enum TraceError {
    IoError(std::io::Error),
    LockError(std::io::Error),

    DecodeError(ctxp::Error),

    TruncatedFile,
    MisalignedEventRegion {
        region_len: usize,
        event_size: usize,
    },
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceError::IoError(e) => write!(f, "I/O error: {e}"),
            TraceError::LockError(e) => write!(f, "failed to lock trace file: {e}"),
            TraceError::TruncatedFile => {
                write!(f, "file is shorter than its declared header/metadata")
            }
            TraceError::MisalignedEventRegion {
                region_len,
                event_size,
            } => write!(
                f,
                "event region length {region_len} is not a multiple of event size {event_size}"
            ),
            TraceError::DecodeError(error) => write!(f, "CTXP decoder failed with error {error}"),
        }
    }
}

impl std::error::Error for TraceError {}

// fn decode_event(bytes: &[u8; TraceFile::EVENT_SIZE]) -> Event {
//     // TODO: real field layout
//     Event {
//         addr: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
//     }
// }

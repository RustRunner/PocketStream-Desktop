//! Size-bounded log-file writer.
//!
//! `fern` pushes every formatted record through `io::Write`; this writer
//! appends to the live log file and, when a write would cross the size
//! cap, renames the live file to a single `.1` survivor generation
//! (replacing the previous one) and starts fresh. The same rotation runs
//! once at open, so the live file only ever holds the current app
//! session and the previous session survives in `.1`. Rotation is by
//! rename, never truncation, so after a crash the relaunch keeps the
//! pre-crash tail on disk in `.1` instead of destroying the history that
//! explains the crash. Steady-state disk use is bounded at two
//! generations.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Cap per generation. Two generations on disk → ~10 MB worst case.
pub const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

pub struct RotatingFileWriter {
    path: PathBuf,
    max: u64,
    /// File handle and byte count together under one lock so the
    /// size check and the write it gates can't interleave.
    state: Mutex<WriterState>,
}

struct WriterState {
    file: File,
    written: u64,
}

impl RotatingFileWriter {
    /// Open the live file for append, then rotate any previous session's
    /// content into the `.1` survivor so the live file starts this
    /// session empty. A crash-then-relaunch therefore keeps the pre-crash
    /// log in `.1` rather than mixing sessions or destroying history; if
    /// the rotation rename fails, the writer appends after the old
    /// content, which is the same degrade path in-session rotation uses.
    pub fn open(path: PathBuf, max: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        let this = Self {
            path,
            max,
            state: Mutex::new(WriterState { file, written }),
        };
        {
            let mut state = this
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.written > 0 {
                this.rotate(&mut state);
            }
        }
        Ok(this)
    }

    /// `pocketstream.log` → `pocketstream.log.1`
    fn rotated_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_owned())
            .unwrap_or_else(|| std::ffi::OsString::from("log"));
        name.push(".1");
        self.path.with_file_name(name)
    }

    /// Rename the live file aside and start a new one. On any failure the
    /// writer degrades to appending in place — a growing file is always
    /// preferable to dropped records. `written` resets either way so a
    /// failed rotation retries once per cap interval, not on every write.
    fn rotate(&self, state: &mut WriterState) {
        let _ = state.file.flush();
        let rotated = self.rotated_path();
        // fs::rename does not replace an existing destination on Windows.
        let _ = std::fs::remove_file(&rotated);
        match std::fs::rename(&self.path, &rotated) {
            Ok(()) => {
                // The old handle now points at the renamed file; open a
                // fresh live file. If that fails, keep the old handle —
                // records then land in the `.1` generation, still on disk.
                match OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    Ok(f) => state.file = f,
                    Err(e) => {
                        // Can't use log:: here — this IS the log sink and
                        // re-entering it would deadlock fern's dispatch.
                        eprintln!("log rotation: reopen after rename failed: {}", e);
                        let _ = writeln!(
                            state.file,
                            "[log rotation] reopen after rename failed ({}); appending here",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("log rotation: rename failed: {}", e);
                let _ = writeln!(
                    state.file,
                    "[log rotation] rename failed ({}); appending in place",
                    e
                );
            }
        }
        state.written = 0;
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Rotate before the write that would cross the cap. The
        // `written > 0` guard keeps a single oversized record from
        // rotating an empty file in a loop.
        if state.written > 0 && state.written + buf.len() as u64 > self.max {
            self.rotate(&mut state);
        }
        let n = state.file.write(buf)?;
        state.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_run(w: &mut RotatingFileWriter, byte: u8, n: usize) {
        w.write_all(&vec![byte; n]).unwrap();
    }

    #[test]
    fn rotation_preserves_earlier_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let mut w = RotatingFileWriter::open(path.clone(), 100).unwrap();
        write_run(&mut w, b'a', 80);
        write_run(&mut w, b'b', 40); // 80 + 40 > 100 → rotates first
        let rotated = std::fs::read_to_string(dir.path().join("test.log.1")).unwrap();
        let live = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rotated, "a".repeat(80));
        assert_eq!(live, "b".repeat(40));
    }

    #[test]
    fn second_rotation_replaces_prior_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let mut w = RotatingFileWriter::open(path.clone(), 100).unwrap();
        write_run(&mut w, b'a', 80);
        write_run(&mut w, b'b', 80); // rotate: .1 = a's, live = b's
        write_run(&mut w, b'c', 80); // rotate: .1 = b's, live = c's
        let rotated = std::fs::read_to_string(dir.path().join("test.log.1")).unwrap();
        let live = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rotated, "b".repeat(80));
        assert_eq!(live, "c".repeat(80));
    }

    #[test]
    fn preexisting_content_rotates_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        std::fs::write(&path, "x".repeat(60)).unwrap(); // under the cap
        let mut w = RotatingFileWriter::open(path.clone(), 100).unwrap();
        // The previous session moved aside before any write of this one.
        let rotated = std::fs::read_to_string(dir.path().join("test.log.1")).unwrap();
        assert_eq!(rotated, "x".repeat(60));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        write_run(&mut w, b'y', 10);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "y".repeat(10));
    }

    #[test]
    fn empty_or_missing_file_does_not_rotate_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let _w = RotatingFileWriter::open(path.clone(), 100).unwrap();
        assert!(!dir.path().join("test.log.1").exists());
    }

    #[test]
    fn failed_rotation_appends_instead_of_dropping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        // A directory at the rotation target makes both the remove and
        // the rename fail, forcing the degrade path.
        std::fs::create_dir(dir.path().join("test.log.1")).unwrap();
        let mut w = RotatingFileWriter::open(path.clone(), 100).unwrap();
        write_run(&mut w, b'a', 80);
        write_run(&mut w, b'b', 40); // rotation attempt fails → append
        let live = std::fs::read_to_string(&path).unwrap();
        assert!(live.contains(&"a".repeat(80)));
        assert!(live.contains(&"b".repeat(40)));
    }
}

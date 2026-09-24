#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

pub struct TempRoot {
    path: PathBuf,
    reparse_points: Vec<PathBuf>,
}

impl TempRoot {
    pub fn new(case: &str) -> Self {
        let base = Path::new(r"D:\temp");
        assert!(base.is_absolute(), "D:/temp test base must be absolute");
        assert!(base.is_dir(), "D:/temp test base must exist");

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must follow the Unix epoch")
            .as_nanos();
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "winfsr-mirrorfs-{case}-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create owned NTFS test root");
        Self {
            path,
            reparse_points: Vec::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn track_reparse_point(&mut self, path: PathBuf) {
        assert_eq!(path.parent(), Some(self.path.as_path()));
        self.reparse_points.push(path);
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        for path in self.reparse_points.iter().rev() {
            let _ = std::fs::remove_dir(path).or_else(|_| std::fs::remove_file(path));
        }

        let owned_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("winfsr-mirrorfs-"));
        if self.path.parent() == Some(Path::new(r"D:\temp")) && owned_name {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

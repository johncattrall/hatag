use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn default_root() -> io::Result<PathBuf> {
    let root = dirs::data_local_dir()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound,
            "Cannot determine the user's application-data directory; specify --state-dir"))?;
    Ok(root.join("hatag"))
}

pub fn state_directory(explicit: Option<&Path>) -> io::Result<PathBuf> {
    explicit.map(Path::to_path_buf).map(Ok).unwrap_or_else(|| Ok(default_root()?.join("state")))
}

pub fn output_directory(explicit: Option<&Path>) -> io::Result<PathBuf> {
    explicit.map(Path::to_path_buf).map(Ok).unwrap_or_else(std::env::current_dir)
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "Storage directory must be a real directory, not a symlink"));
    }
    Ok(())
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    ensure_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn check_writable(path: &Path) -> io::Result<()> {
    let probe = path.join(format!(".hatag-write-check-{}", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&probe)?;
    let result = file.write_all(b"hatag");
    drop(file);
    let removal = fs::remove_file(probe);
    result.and(removal)
}

pub fn require_writable_directory(path: &Path, option: &str) -> io::Result<()> {
    private_directory(path).and_then(|_| check_writable(path)).map_err(|error| {
        io::Error::new(error.kind(), format!(
            "Cannot write to {}: {error}. Choose a directory you own with {option}; do not use sudo.",
            path.display()
        ))
    })
}

pub fn require_writable_output_directory(path: &Path) -> io::Result<()> {
    // Never chmod a user's working directory or an existing output directory.
    ensure_directory(path).and_then(|_| check_writable(path)).map_err(|error| {
        let message = if error.kind() == io::ErrorKind::PermissionDenied {
            format!("You do not have write access to {}. Please change to a writable directory or specify --output-dir PATH; do not use sudo.", path.display())
        } else {
            format!("Cannot use output directory {}: {error}. Please change to a writable directory or specify --output-dir PATH.", path.display())
        };
        io::Error::new(error.kind(), message)
    })
}

pub fn check_existing_state_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("State file {} must be a regular file, not a symlink", path.display())));
        }
        Ok(_) => {},
    }
    OpenOptions::new().read(true).write(true).open(path).map_err(|error| {
        io::Error::new(error.kind(), format!(
            "Cannot read and update {}: {error}. Use --state-dir with a directory you own.", path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_per_user_but_output_defaults_to_current_directory() {
        let root = dirs::data_local_dir().unwrap().join("hatag");
        assert_eq!(state_directory(None).unwrap(), root.join("state"));
        assert_eq!(output_directory(None).unwrap(), std::env::current_dir().unwrap());
        assert!(state_directory(None).unwrap().is_absolute());
        assert_eq!(state_directory(Some(Path::new("legacy"))).unwrap(), Path::new("legacy"));
        assert_eq!(output_directory(Some(Path::new("./exports"))).unwrap(), Path::new("./exports"));
    }

    #[test]
    fn preflight_rejects_files_and_leaves_no_probe() {
        let root = std::env::temp_dir().join(format!("hatag-paths-{}", uuid::Uuid::new_v4()));
        require_writable_directory(&root, "--state-dir").unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let file = root.join("not-a-directory");
        fs::write(&file, b"preserved").unwrap();
        assert!(require_writable_directory(&file, "--state-dir").is_err());
        assert_eq!(fs::read(&file).unwrap(), b"preserved");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_symlinks_and_unwritable_directories_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = std::env::temp_dir().join(format!("hatag-permissions-{}", uuid::Uuid::new_v4()));
        private_directory(&root).unwrap();
        let state = root.join("state.plist");
        fs::write(&state, b"preserved").unwrap();
        let link = root.join("linked.plist");
        symlink(&state, &link).unwrap();
        assert!(check_existing_state_file(&link).is_err());
        assert_eq!(fs::read(&state).unwrap(), b"preserved");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(check_existing_state_file(&state).is_err());
            fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
            assert!(require_writable_output_directory(&root.join("child")).is_err());
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn output_checks_preserve_existing_permissions_and_probe_cleanup() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("hatag-output-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        require_writable_output_directory(&root).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            let error = require_writable_output_directory(&root).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o555);
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(root).unwrap();
    }
}

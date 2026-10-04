use super::{LinuxManagedAreaRoot, ManagedAreaError};
use std::path::{Component, Path, PathBuf};

impl LinuxManagedAreaRoot {
    /// Opens only the calling daemon's current delegated cgroup-v2 directory.
    /// The path comes from kernel procfs and is opened without following links.
    pub fn open_current_cgroup() -> Result<Self, ManagedAreaError> {
        let membership = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|_| ManagedAreaError::Unavailable)?;
        let group = parse_membership(&membership)?;
        let mounts = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|_| ManagedAreaError::Unavailable)?;
        let root = resolve_mount(&mounts, &group)?;
        Self::open(&root)
    }
}

fn parse_membership(text: &str) -> Result<PathBuf, ManagedAreaError> {
    let mut unified = text.lines().filter_map(|line| {
        let (controllers, path) = line.split_once(':')?;
        let (controllers, path) = (controllers, path.strip_prefix(':')?);
        (controllers == "0" && path.starts_with('/')).then(|| PathBuf::from(path))
    });
    let path = unified.next().ok_or(ManagedAreaError::Unavailable)?;
    if unified.next().is_some() || !safe_components(&path) {
        return Err(ManagedAreaError::Unverified);
    }
    Ok(path)
}

fn resolve_mount(mountinfo: &str, membership: &Path) -> Result<PathBuf, ManagedAreaError> {
    let mut matches = Vec::new();
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            return Err(ManagedAreaError::Unavailable);
        };
        if right.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = left.split_whitespace().collect();
        let root = decode_mount(fields.get(3).ok_or(ManagedAreaError::Unavailable)?)?;
        let point = decode_mount(fields.get(4).ok_or(ManagedAreaError::Unavailable)?)?;
        let root = PathBuf::from(root);
        let point = PathBuf::from(point);
        if safe_components(&root) && safe_components(&point) {
            matches.extend(
                membership
                    .strip_prefix(&root)
                    .map(|relative| point.join(relative)),
            );
        }
    }
    if matches.len() != 1 {
        return Err(ManagedAreaError::Unavailable);
    }
    let path = matches.pop().ok_or(ManagedAreaError::Unavailable)?;
    if !safe_components(&path) {
        return Err(ManagedAreaError::Unverified);
    }
    Ok(path)
}

fn safe_components(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn decode_mount(raw: &str) -> Result<String, ManagedAreaError> {
    let mut bytes = Vec::with_capacity(raw.len());
    let input = raw.as_bytes();
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'\\' {
            bytes.push(input[index]);
            index += 1;
            continue;
        }
        let digits = input
            .get(index + 1..index + 4)
            .ok_or(ManagedAreaError::Unverified)?;
        if !digits.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
            return Err(ManagedAreaError::Unverified);
        }
        let value = ((digits[0] - b'0') << 6) | ((digits[1] - b'0') << 3) | (digits[2] - b'0');
        bytes.push(value);
        index += 4;
    }
    String::from_utf8(bytes).map_err(|_| ManagedAreaError::Unverified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_only_the_exact_unified_membership_under_cgroup2_mount() {
        let membership = parse_membership("5:cpu:/ignored\n0::/user.slice/app.scope\n").unwrap();
        let mount = "36 25 0:32 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw";
        assert_eq!(
            resolve_mount(mount, &membership).unwrap(),
            Path::new("/sys/fs/cgroup/user.slice/app.scope")
        );
    }

    #[test]
    fn rejects_ambiguous_or_traversing_membership_and_mounts() {
        assert!(parse_membership("0::/a\n0::/b\n").is_err());
        assert!(parse_membership("0::/../escape\n").is_err());
        assert!(
            resolve_mount(
                "36 25 0:32 /other /sys/fs/cgroup rw - cgroup2 cgroup2 rw",
                Path::new("/user.slice/app.scope")
            )
            .is_err()
        );
    }
}

use super::*;

pub(super) fn run(
    root: &File,
    tool: &str,
    args: &coding_arguments::CodingArguments,
) -> Result<Vec<u8>, &'static str> {
    let mut pending = vec![(args.path.clone(), 0usize)];
    let mut found = Vec::new();
    let mut visited = 0;
    let mut truncated = false;
    while let Some((path, depth)) = pending.pop() {
        let dir = coding_fs::open(root, &path, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let mut names: Vec<String> = read_dir(&dir)?
            .into_iter()
            .filter_map(|name| name.into_string().ok())
            .collect();
        names.sort();
        for name in names {
            visited += 1;
            if visited > 1000 {
                truncated = true;
                break;
            }
            if name == ".git" || name == ".env" || name.starts_with(".env.") || name == ".ssh" {
                continue;
            }
            let child = if path == "." {
                name.clone()
            } else {
                format!("{path}/{name}")
            };
            if runne_security::project_trust_policy::normalize_source_path(&child)
                .map(|parts| runne_security::project_trust_policy::denied_by_frozen_set(&parts))
                .unwrap_or(true)
            {
                continue;
            }
            let info = stat_at(&dir, std::ffi::OsStr::new(&name))?;
            if info.st_mode & libc::S_IFMT == libc::S_IFLNK {
                continue;
            }
            if info.st_mode & libc::S_IFMT == libc::S_IFDIR {
                if depth < 16 {
                    pending.push((child, depth + 1));
                } else {
                    truncated = true;
                }
            } else if info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_nlink == 1 {
                if tool == "workspace.files.list" {
                    found.push(serde_json::json!({"path":child,"bytes":info.st_size}));
                } else if let Ok(bytes) = coding_fs::bounded_read(root, &child)
                    && let Ok(text) = std::str::from_utf8(&bytes)
                {
                    for (line, text) in text.lines().enumerate() {
                        if text.contains(&args.query) {
                            found.push(serde_json::json!({"path":child,"line":line+1,"text":text.chars().take(256).collect::<String>()}));
                            if found.len() >= args.limit {
                                break;
                            }
                        }
                    }
                }
            }
            if found.len() >= args.limit {
                truncated = true;
                break;
            }
        }
        if truncated || found.len() >= args.limit {
            break;
        }
    }
    loop {
        let encoded =
            serde_json::to_vec(&serde_json::json!({"entries":found,"truncated":truncated}))
                .map_err(|_| "output_invalid")?;
        if encoded.len() <= MAX_CONTENT {
            return Ok(encoded);
        }
        if found.pop().is_none() {
            return Err("output_bound");
        }
        truncated = true;
    }
}

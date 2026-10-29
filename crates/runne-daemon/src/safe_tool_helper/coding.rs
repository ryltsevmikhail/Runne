use super::*;

pub(super) fn execute(
    root: &File,
    binding: BindingV1,
    tool: &str,
    arguments: &serde_json::Value,
    expected_root: IdentityV1,
    expected: Option<VersionV1>,
) -> Result<ReceiptV1, &'static str> {
    validate_binding(&binding)?;
    let args = coding_arguments::parse(tool, arguments).map_err(|_| "invalid_arguments")?;
    let root_identity = identity(root)?;
    if root_identity != expected_root {
        return Err("root_changed");
    }
    let before = coding_fs::capture(root, tool, &args.path)?;
    if before != expected {
        return Err("target_changed");
    }
    let mut completed_target = None;
    let bytes = match tool {
        "workspace.file.read" => coding_fs::bounded_read(root, &args.path)?,
        "workspace.file.create_new" => {
            let file = coding_fs::open(
                root,
                &args.path,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            )?;
            write_all(&file, &args.content).map_err(effect_error)?;
            if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
                return Err("effect_started_sync_failed");
            }
            if !regular_single(&file).map_err(effect_error)?
                || coding_fs::snapshot(root, &args.path, false).map_err(effect_error)?
                    != version(&file).map_err(effect_error)?
                || read_bounded(&file, args.content.len()).map_err(effect_error)? != args.content
            {
                return Err("effect_started_target_changed");
            }
            completed_target = Some(version(&file).map_err(effect_error)?);
            args.content.clone()
        }
        "workspace.file.replace" => {
            let (bytes, target) = replace(root, &args, before.as_ref().ok_or("target_missing")?)?;
            completed_target = Some(target);
            bytes
        }
        "workspace.files.list" | "workspace.files.search" => {
            coding_listing::run(root, tool, &args)?
        }
        "workspace.command.run" => coding_command::run(root, &args)?,
        _ => return Err("unknown_operation"),
    };
    let directory = matches!(
        tool,
        "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
    );
    let target = coding_fs::snapshot(root, &args.path, directory).map_err(effect_error)?;
    if completed_target.is_some_and(|completed| completed != target) {
        return Err("effect_started_target_changed");
    }
    if identity(root).map_err(effect_error)? != root_identity {
        return Err("effect_started_root_changed");
    }
    if tool == "workspace.file.read" && Some(&target) != before.as_ref() {
        return Err("effect_started_target_changed");
    }
    let mut output = receipt(
        coding_arguments::operation(tool).map_err(|_| "unknown_operation")?,
        binding,
        CString::new(args.path).map_err(|_| "path_denied")?,
        root_identity,
        target,
        bytes,
    )
    .map_err(effect_error)?;
    output.version = 2;
    Ok(output)
}
fn replace(
    root: &File,
    args: &coding_arguments::CodingArguments,
    expected: &VersionV1,
) -> Result<(Vec<u8>, VersionV1), &'static str> {
    let file = coding_fs::open(root, &args.path, libc::O_RDWR | libc::O_NONBLOCK)?;
    if !regular_single(&file)? || &version(&file)? != expected {
        return Err("target_changed");
    }
    let old = read_bounded(&file, expected.size as usize)?;
    if args.expected_sha256.as_deref() != Some(hex::encode(Sha256::digest(&old)).as_str())
        || &version(&file)? != expected
    {
        return Err("target_changed");
    }
    // The held inode is approved. A raced name replacement never redirects this write.
    write_all(&file, &args.content).map_err(effect_error)?;
    if unsafe { libc::ftruncate(file.as_raw_fd(), args.content.len() as libc::off_t) } != 0
        || unsafe { libc::fsync(file.as_raw_fd()) } != 0
    {
        return Err("effect_started_sync_failed");
    }
    let after = version(&file).map_err(effect_error)?;
    if coding_fs::snapshot(root, &args.path, false).map_err(effect_error)? != after
        || read_bounded(&file, args.content.len()).map_err(effect_error)? != args.content
    {
        return Err("effect_started_target_changed");
    }
    Ok((args.content.clone(), after))
}

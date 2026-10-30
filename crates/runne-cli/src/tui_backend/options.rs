use std::{collections::VecDeque, ffi::OsString, path::PathBuf};

pub const HELP: &str = include_str!("help.txt");

pub struct Options {
    pub project: PathBuf,
    pub profile: Option<PathBuf>,
    pub resume: Option<String>,
    pub picker: bool,
}

pub fn selected(arguments: &[OsString]) -> bool {
    arguments.is_empty()
        || arguments.first().is_some_and(|arg| arg == "chat")
        || (arguments.first().is_some_and(|arg| arg == "--profile")
            && arguments.get(2).is_some_and(|arg| arg == "chat"))
}

pub fn parse(arguments: Vec<OsString>) -> Result<Options, String> {
    let mut args = VecDeque::from(arguments);
    let mut profile = if args.front().is_some_and(|a| a == "--profile") {
        args.pop_front();
        Some(PathBuf::from(
            args.pop_front().ok_or("Missing profile path")?,
        ))
    } else {
        None
    };
    if args.front().is_some_and(|a| a == "chat") {
        args.pop_front();
    }
    let mut project = None;
    let mut resume = None;
    let mut picker = false;
    while let Some(arg) = args.pop_front() {
        match arg.to_str() {
            Some("--project") if project.is_none() => {
                project = Some(PathBuf::from(
                    args.pop_front().ok_or("Missing project path")?,
                ));
            }
            Some("--profile") if profile.is_none() => {
                profile = Some(PathBuf::from(
                    args.pop_front().ok_or("Missing profile path")?,
                ));
            }
            Some("--resume") if !picker => {
                picker = true;
                if args
                    .front()
                    .is_some_and(|a| a.to_str().is_some_and(|s| !s.starts_with('-')))
                {
                    resume = Some(
                        args.pop_front()
                            .and_then(|a| a.into_string().ok())
                            .ok_or("Invalid session ID")?,
                    );
                }
            }
            _ => return Err(HELP.into()),
        }
    }
    if let Some(id) = &resume {
        runne_runtime_client::CanonicalId::parse(id).map_err(|_| "Invalid session ID")?;
    }
    Ok(Options {
        project: project
            .map_or_else(std::env::current_dir, Ok)
            .map_err(|_| "Current directory unavailable")?,
        profile,
        resume,
        picker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_resume_picker_and_profile_without_changing_legacy_dispatch() {
        let options = parse(
            ["chat", "--resume", "--project", "/tmp", "--profile", "p"]
                .into_iter()
                .map(Into::into)
                .collect(),
        )
        .unwrap();
        assert!(options.picker);
        assert!(options.resume.is_none());
        assert_eq!(options.project, PathBuf::from("/tmp"));
        assert!(!selected(&["exec".into()]));
        assert!(!selected(&[
            "--format".into(),
            "json".into(),
            "session".into(),
            "list".into()
        ]));
        assert!(selected(&[]));
    }
    #[test]
    fn rejects_duplicate_options_and_invalid_resume() {
        assert!(
            parse(
                ["chat", "--resume", "not-an-id"]
                    .into_iter()
                    .map(Into::into)
                    .collect()
            )
            .is_err()
        );
        assert!(
            parse(
                ["chat", "--project", "/tmp", "--project", "/var"]
                    .into_iter()
                    .map(Into::into)
                    .collect()
            )
            .is_err()
        );
    }
}

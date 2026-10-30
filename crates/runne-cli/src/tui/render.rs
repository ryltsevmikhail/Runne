use super::state::{Panel, State};
use crossterm::{
    cursor, queue,
    style::Print,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use unicode_width::UnicodeWidthChar;

// Untrusted text is stripped of CSI, OSC, DCS and terminal/bidi controls.
pub(super) fn sanitize(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.next() {
                Some('[') => {
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']' | 'P' | '^' | '_' | 'X') => {
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if ch == '\n' {
            output.push(ch);
        } else if ch == '\t' {
            output.push_str("    ");
        } else if !ch.is_control()
            && !matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            output.push(ch);
        }
    }
    output
}

fn wrap(value: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    let mut used = 0;
    for ch in sanitize(value).chars() {
        if ch == '\n' {
            lines.push(String::new());
            used = 0;
            continue;
        }
        let size = ch.width().unwrap_or(0);
        if size > width {
            continue;
        }
        if used + size > width {
            lines.push(String::new());
            used = 0;
        }
        lines.last_mut().expect("one line").push(ch);
        used += size;
    }
    lines
}

pub(super) fn lines(state: &State, width: u16, height: u16) -> Vec<String> {
    let width = usize::from(width.max(1));
    let height = usize::from(height);
    if height == 0 {
        return vec![];
    }
    let header = format!(
        "Runne | {} | {}",
        state.snapshot.model, state.snapshot.session
    );
    let content = match state.panel {
        Panel::Chat if state.snapshot.status.starts_with("Project registration") => format!(
            "Project root:\n{}\n\n{}\n/register explicitly trusts this root for runtime actions.",
            state.snapshot.project, state.snapshot.status
        ),
        Panel::Chat => state.snapshot.messages.join("\n\n"),
        Panel::Actions => format!("Actions / command output\n{}", state.snapshot.actions.join("\n\n")),
        Panel::Diff => format!("Proposed / recorded diff\n{}", state.snapshot.diff),
        Panel::Permissions => state.snapshot.approvals.iter().enumerate().map(|(i, a)| format!("{} {}\n{}\n[y] approve this action / [n] deny", if i == state.selection { ">" } else { " " }, a.title, a.detail)).collect::<Vec<_>>().join("\n\n"),
        Panel::Sessions => format!("Sessions — type to search: {}\n{}", state.query, state.sessions().iter().enumerate().map(|(i, s)| format!("{} {}  {}", if i == state.selection { ">" } else { " " }, s.title, s.updated)).collect::<Vec<_>>().join("\n")),
        Panel::Help => "Enter send · Alt+Enter newline · paste never sends\nCtrl+C cancel active task · Ctrl+Q quit client\nCtrl+N new session · Ctrl+R refresh\nF2 sessions/search · F3 actions/output · F4 diff · F5 permissions\nUp/Down select session or approval · Enter open session\nPageUp/PageDown scroll · Esc chat\n/register trusts the displayed project root through runtime\n/login deepseek stores the provider key in Keychain (input hidden)\n/new /sessions /diff /permissions /help /quit\nApproval: y allows the selected exact action, n denies it.\nQuit waits for a safe runtime exit; active or uncertain tasks must resolve first.".into(),
    };
    let mut result = vec![wrap(&header, width).remove(0)];
    if height < 6 {
        result.extend(wrap("Terminal too small; resize or Ctrl+Q", width));
        result.truncate(height);
        return result;
    }
    result.push(wrap(&format!("Status: {}", state.snapshot.status), width).remove(0));
    result.push(wrap(&format!("Project: {}", state.snapshot.project), width).remove(0));
    let header_height = result.len();
    let input = if state.credential_prompt.is_some() {
        wrap("> [input hidden] · Enter enroll · Esc cancel", width)
    } else {
        wrap(&format!("> {}", state.editor.display()), width)
    };
    let input_height = input
        .len()
        .min(5)
        .min(height.saturating_sub(header_height + 3))
        .max(1);
    let available = height.saturating_sub(input_height + header_height + 2);
    let body = wrap(&content, width);
    let (start, end) = if matches!(
        state.panel,
        Panel::Sessions | Panel::Help | Panel::Permissions
    ) {
        let selected = body
            .iter()
            .position(|line| line.starts_with("> "))
            .unwrap_or(0);
        let start = selected
            .saturating_sub(available / 2)
            .saturating_add(state.scroll)
            .min(body.len().saturating_sub(1));
        (start, (start + available).min(body.len()))
    } else {
        let end = body
            .len()
            .saturating_sub(state.scroll.min(body.len().saturating_sub(1)));
        (end.saturating_sub(available), end)
    };
    result.extend(body[start..end].iter().cloned());
    while result.len() < available + header_height {
        result.push(String::new());
    }
    result.push(
        wrap(
            &format!(
                "{} | F1 help · F2 sessions · F3 output · F4 diff · F5 approvals",
                state.notice
            ),
            width,
        )
        .remove(0),
    );
    result.extend(
        input
            .into_iter()
            .rev()
            .take(input_height)
            .collect::<Vec<_>>()
            .into_iter()
            .rev(),
    );
    result.push(
        wrap(
            "Enter send · Alt+Enter newline · Ctrl+C cancel · Ctrl+Q quit",
            width,
        )
        .remove(0),
    );
    result.truncate(height);
    result
}

pub(super) fn draw(state: &State) -> io::Result<()> {
    let (width, height) = terminal::size()?;
    let mut out = io::stdout().lock();
    for (index, line) in lines(state, width, height).iter().enumerate() {
        queue!(
            out,
            cursor::MoveTo(0, u16::try_from(index).unwrap_or(u16::MAX)),
            terminal::Clear(ClearType::CurrentLine),
            Print(line)
        )?;
    }
    out.flush()
}

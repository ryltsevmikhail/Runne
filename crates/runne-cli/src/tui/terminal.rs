use crossterm::{cursor, event, execute, terminal};
use std::io::{self, IsTerminal, Write};

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

pub(super) struct Terminal {
    previous_hook: Option<std::sync::Arc<PanicHook>>,
}

fn restore() {
    let _ = execute!(
        io::stdout(),
        event::DisableBracketedPaste,
        cursor::Show,
        terminal::LeaveAlternateScreen
    );
    let _ = terminal::disable_raw_mode();
    let _ = io::stdout().flush();
}

impl Terminal {
    pub fn enter() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::other("Interactive chat requires a terminal"));
        }
        let previous = std::sync::Arc::new(std::panic::take_hook());
        let hook = previous.clone();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            hook(info);
        }));
        let guard = Self {
            previous_hook: Some(previous),
        };
        terminal::enable_raw_mode()?;
        execute!(
            io::stdout(),
            terminal::EnterAlternateScreen,
            event::EnableBracketedPaste,
            cursor::Hide
        )?;
        Ok(guard)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        restore();
        if !std::thread::panicking() {
            let _ = std::panic::take_hook();
            if let Some(previous) = self.previous_hook.take() {
                std::panic::set_hook(Box::new(move |info| previous(info)));
            }
        }
    }
}

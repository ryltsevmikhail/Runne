use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Default)]
pub(super) struct Editor {
    text: String,
    cursor: usize,
}

impl Editor {
    #[cfg(test)]
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn restore_rejected(&mut self, mut rejected: String, newer: &str) {
        if !newer.is_empty() {
            rejected.push_str("\n\n");
            rejected.push_str(newer);
        }
        self.cursor = rejected.len();
        self.text = rejected;
    }

    pub fn take(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.text)
    }

    pub fn paste(&mut self, value: &str) {
        let value = value.replace("\r\n", "\n").replace('\r', "\n");
        for ch in value
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        {
            if self.text.len() >= 64 * 1024 {
                break;
            }
            self.text.insert(self.cursor, ch);
            self.cursor += ch.len_utf8();
        }
    }

    pub fn key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.paste(&c.to_string());
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) => self.paste("\n"),
            KeyCode::Left => {
                self.cursor = self.text[..self.cursor]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(i, _)| i);
            }
            KeyCode::Right => {
                self.cursor += self.text[self.cursor..]
                    .chars()
                    .next()
                    .map_or(0, char::len_utf8);
            }
            KeyCode::Up => self.vertical(false),
            KeyCode::Down => self.vertical(true),
            KeyCode::Home => {
                self.cursor = self.text[..self.cursor].rfind('\n').map_or(0, |i| i + 1);
            }
            KeyCode::End => {
                self.cursor += self.text[self.cursor..]
                    .find('\n')
                    .unwrap_or(self.text.len() - self.cursor);
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let previous = self.text[..self.cursor]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(i, _)| i);
                self.text.drain(previous..self.cursor);
                self.cursor = previous;
            }
            KeyCode::Delete if self.cursor < self.text.len() => {
                self.text.remove(self.cursor);
            }
            _ => {}
        }
    }

    fn vertical(&mut self, down: bool) {
        use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
        let start = self.text[..self.cursor].rfind('\n').map_or(0, |i| i + 1);
        let column = self.text[start..self.cursor].width();
        let target = if down {
            match self.text[self.cursor..].find('\n') {
                Some(i) => self.cursor + i + 1,
                None => return,
            }
        } else if start == 0 {
            return;
        } else {
            self.text[..start - 1].rfind('\n').map_or(0, |i| i + 1)
        };
        self.cursor = target;
        let mut used = 0;
        for ch in self.text[target..].chars() {
            if ch == '\n' || used + ch.width().unwrap_or(0) > column {
                break;
            }
            used += ch.width().unwrap_or(0);
            self.cursor += ch.len_utf8();
        }
    }

    pub fn display(&self) -> String {
        let mut value = self.text.clone();
        value.insert(self.cursor, '▏');
        value
    }
}

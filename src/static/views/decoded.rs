use crate::r#static::types::View;

pub fn build(values: &[String]) -> View {
    View::new("decoded.values", limited_join(values, 128, 16 * 1024))
}

fn limited_join(values: &[String], max_items: usize, max_bytes: usize) -> String {
    let mut content = String::new();
    let mut emitted = 0usize;

    for value in values.iter().take(max_items) {
        append_limited_line(&mut content, value, max_bytes);
        if content.len() >= max_bytes {
            break;
        }
        emitted += 1;
    }

    if values.len() > emitted || content.len() >= max_bytes {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str("... truncated preview");
    }

    content
}

fn append_limited_line(content: &mut String, value: &str, max_bytes: usize) {
    if content.len() >= max_bytes {
        return;
    }
    if !content.is_empty() && content.len() < max_bytes {
        content.push('\n');
    }

    let remaining = max_bytes.saturating_sub(content.len());
    if remaining == 0 {
        return;
    }
    if value.len() <= remaining {
        content.push_str(value);
        return;
    }

    let mut end = remaining;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    content.push_str(&value[..end]);
}

pub mod ascii;
pub mod dedupe;
pub mod extractor;
pub mod pool;
pub mod raw;
pub mod utf16;
pub mod utf8;

use super::context::ScanContext;

pub fn run(ctx: &mut ScanContext) {
    let extracted = extractor::extract_all(&ctx.bytes);
    let mut deduped = dedupe::stable_dedupe(extracted);
    let limit = ctx.config.limits.max_string_values;
    if deduped.len() > limit {
        deduped.truncate(limit);
        ctx.log_event(
            "strings",
            format!("String extraction capped at {} values", limit),
        );
    }

    let mut preview = String::new();
    let mut emitted = 0usize;
    for value in deduped.iter().take(ctx.config.limits.max_view_items) {
        if !preview.is_empty() && preview.len() < ctx.config.limits.max_view_bytes {
            preview.push('\n');
        }
        append_limited(&mut preview, value, ctx.config.limits.max_view_bytes);
        if preview.len() >= ctx.config.limits.max_view_bytes {
            break;
        }
        emitted += 1;
    }
    if deduped.len() > emitted || preview.len() >= ctx.config.limits.max_view_bytes {
        if !preview.is_empty() {
            preview.push('\n');
        }
        preview.push_str("... truncated preview");
    }

    ctx.strings.extend(deduped);
    ctx.push_view(super::types::View::new("strings.preview", preview));
}

fn append_limited(output: &mut String, value: &str, max_bytes: usize) {
    let remaining = max_bytes.saturating_sub(output.len());
    if remaining == 0 {
        return;
    }
    if value.len() <= remaining {
        output.push_str(value);
        return;
    }

    let mut end = remaining;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&value[..end]);
}

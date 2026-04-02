pub mod casing;
pub mod cleanup;
pub mod concat;
pub mod escape;
pub mod unicode;
pub mod whitespace;

use super::context::ScanContext;
use super::strings::dedupe;

pub fn run(ctx: &mut ScanContext) {
    let mut normalized = Vec::new();
    for value in ctx
        .strings
        .values
        .iter()
        .take(ctx.config.limits.max_string_values)
    {
        let v1 = whitespace::collapse(value);
        let v2 = casing::to_lower(&v1);
        let v3 = escape::unescape_basic(&v2);
        let v4 = unicode::decode_percent_hex(&v3);
        let v5 = concat::simplify_js_concat(&v4);
        let v6 = cleanup::trim_noise(&v5);
        if v6.is_empty() {
            continue;
        }
        normalized.push(v6);
    }

    let mut normalized = dedupe::stable_dedupe(normalized);
    if normalized.len() > ctx.config.limits.max_string_values {
        normalized.truncate(ctx.config.limits.max_string_values);
        ctx.log_event(
            "normalize",
            format!(
                "Normalized strings capped at {} values",
                ctx.config.limits.max_string_values
            ),
        );
    }
    if normalized.is_empty() {
        return;
    }

    ctx.normalized_strings = normalized;
    ctx.push_view(super::views::normalized::build(&ctx.normalized_strings));
}

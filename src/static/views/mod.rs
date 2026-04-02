pub mod decoded;
pub mod normalized;
pub mod raw;
pub mod sections;
pub mod strings;

use super::context::ScanContext;

pub fn run(ctx: &mut ScanContext) {
    ctx.push_view(raw::build(&ctx.bytes));
    ctx.push_view(strings::build(&ctx.bytes));
    ctx.push_view(sections::build(&ctx.bytes));
}

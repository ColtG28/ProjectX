pub mod decision;
pub mod indicators;
pub mod score;
pub mod weights;

use super::context::ScanContext;
use super::types::Severity;

pub fn run(ctx: &mut ScanContext) -> Severity {
    let weighted = score::calculate(&ctx.findings);
    ctx.score.risk = weighted;
    ctx.score.safety = 10.0 - weighted;
    decision::classify(weighted, &ctx.config.thresholds)
}

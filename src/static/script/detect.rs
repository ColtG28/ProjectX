#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    PowerShell,
    JavaScript,
    Vba,
    Batch,
    Unknown,
}

pub fn kind(input: &str) -> ScriptKind {
    let lower = input.to_ascii_lowercase();
    if lower.contains("powershell")
        || lower.contains("-enc")
        || lower.contains("invoke-expression")
        || lower.contains("iex")
        || lower.contains("new-object net.webclient")
    {
        ScriptKind::PowerShell
    } else if lower.contains("function(")
        || lower.contains("eval(")
        || lower.contains("fromcharcode")
        || lower.contains("activexobject")
    {
        ScriptKind::JavaScript
    } else if lower.contains("sub ") || lower.contains("createobject") || lower.contains("autoopen")
    {
        ScriptKind::Vba
    } else if lower.contains("@echo off")
        || lower.contains("cmd /c")
        || lower.contains("regsvr32")
        || lower.contains("rundll32")
    {
        ScriptKind::Batch
    } else {
        ScriptKind::Unknown
    }
}

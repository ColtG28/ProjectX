use serde::{Deserialize, Serialize};

use crate::r#static::types::{DynamicBehaviorEvent, DynamicBehaviorSummary};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehaviorEventKind {
    FileCreate,
    FileModify,
    RegistryWrite,
    NetworkConnect,
    ProcessSpawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub kind: BehaviorEventKind,
    pub subject: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorReport {
    pub file_events: usize,
    pub registry_events: usize,
    pub network_events: usize,
    pub process_events: usize,
}

pub fn summarize(events: &[BehaviorEvent]) -> BehaviorReport {
    let mut report = BehaviorReport::default();
    for event in events {
        match event.kind {
            BehaviorEventKind::FileCreate | BehaviorEventKind::FileModify => {
                report.file_events += 1
            }
            BehaviorEventKind::RegistryWrite => report.registry_events += 1,
            BehaviorEventKind::NetworkConnect => report.network_events += 1,
            BehaviorEventKind::ProcessSpawn => report.process_events += 1,
        }
    }
    report
}

pub fn parse_trace_log(trace: &str, max_events: usize) -> Vec<BehaviorEvent> {
    let mut events = Vec::new();

    for line in trace.lines() {
        if events.len() >= max_events {
            break;
        }

        let normalized = line.trim();
        if normalized.is_empty() {
            continue;
        }

        if let Some(subject) = syscall_subject(normalized, "execve(") {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::ProcessSpawn,
                subject,
            });
            continue;
        }

        if let Some(subject) =
            syscall_subject(normalized, "openat(").or_else(|| syscall_subject(normalized, "open("))
        {
            let kind = if normalized.contains("O_WRONLY")
                || normalized.contains("O_RDWR")
                || normalized.contains("O_CREAT")
                || normalized.contains("O_TRUNC")
            {
                BehaviorEventKind::FileModify
            } else {
                BehaviorEventKind::FileCreate
            };
            events.push(BehaviorEvent { kind, subject });
            continue;
        }

        if let Some(subject) = syscall_subject(normalized, "connect(") {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::NetworkConnect,
                subject,
            });
            continue;
        }

        if let Some(subject) = registry_subject(normalized) {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::RegistryWrite,
                subject,
            });
        }
    }

    events
}

pub fn parse_procmon_csv(csv: &str, max_events: usize) -> Vec<BehaviorEvent> {
    let mut events = Vec::new();

    for line in csv.lines().skip(1) {
        if events.len() >= max_events {
            break;
        }
        let columns = line.split(',').map(str::trim).collect::<Vec<_>>();
        if columns.len() < 5 {
            continue;
        }

        let operation = columns[3].to_ascii_lowercase();
        let path = columns[4].to_string();
        let kind = if operation.contains("createfile") || operation.contains("writefile") {
            Some(BehaviorEventKind::FileModify)
        } else if operation.contains("regsetvalue") || operation.contains("regcreatekey") {
            Some(BehaviorEventKind::RegistryWrite)
        } else if operation.contains("tcp connect") || operation.contains("udp send") {
            Some(BehaviorEventKind::NetworkConnect)
        } else if operation.contains("process create") {
            Some(BehaviorEventKind::ProcessSpawn)
        } else {
            None
        };

        if let Some(kind) = kind {
            events.push(BehaviorEvent {
                kind,
                subject: path,
            });
        }
    }

    events
}

pub fn into_dynamic_summary(events: &[BehaviorEvent]) -> DynamicBehaviorSummary {
    let report = summarize(events);
    DynamicBehaviorSummary {
        file_events: report.file_events,
        registry_events: report.registry_events,
        network_events: report.network_events,
        process_events: report.process_events,
    }
}

pub fn into_dynamic_events(events: &[BehaviorEvent]) -> Vec<DynamicBehaviorEvent> {
    events
        .iter()
        .map(|event| DynamicBehaviorEvent {
            kind: match event.kind {
                BehaviorEventKind::FileCreate => "file-create".to_string(),
                BehaviorEventKind::FileModify => "file-modify".to_string(),
                BehaviorEventKind::RegistryWrite => "registry-write".to_string(),
                BehaviorEventKind::NetworkConnect => "network-connect".to_string(),
                BehaviorEventKind::ProcessSpawn => "process-spawn".to_string(),
            },
            subject: event.subject.clone(),
        })
        .collect()
}

fn syscall_subject(line: &str, needle: &str) -> Option<String> {
    let start = line.find(needle)?;
    let text = &line[start + needle.len()..];
    let quote_start = text.find('"')?;
    let text = &text[quote_start + 1..];
    let quote_end = text.find('"')?;
    Some(text[..quote_end].to_string())
}

fn registry_subject(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("reg add ")
        || lower.contains("new-itemproperty")
        || lower.contains("set-itemproperty")
    {
        Some(line.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_procmon_csv, parse_trace_log, summarize, BehaviorEvent, BehaviorEventKind};

    #[test]
    fn summarizes_behavioral_events() {
        let report = summarize(&[
            BehaviorEvent {
                kind: BehaviorEventKind::FileCreate,
                subject: "a".to_string(),
            },
            BehaviorEvent {
                kind: BehaviorEventKind::NetworkConnect,
                subject: "b".to_string(),
            },
        ]);
        assert_eq!(report.file_events, 1);
        assert_eq!(report.network_events, 1);
    }

    #[test]
    fn parses_strace_like_behavior_events() {
        let trace = r#"
123 execve("/tmp/sample.bin", ["sample.bin"], 0x0) = 0
123 openat(AT_FDCWD, "/tmp/dropper.tmp", O_WRONLY|O_CREAT, 0600) = 3
123 connect(3, "198.51.100.10:80", 16) = -1
"#;
        let events = parse_trace_log(trace, 16);
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0].kind, BehaviorEventKind::ProcessSpawn));
        assert!(matches!(events[2].kind, BehaviorEventKind::NetworkConnect));
    }

    #[test]
    fn parses_procmon_csv_events() {
        let csv = "Time,Process Name,PID,Operation,Path\n\
12:00,sample.exe,100,CreateFile,C:\\Temp\\drop.bin\n\
12:00,sample.exe,100,TCP Connect,198.51.100.10:80\n";
        let events = parse_procmon_csv(csv, 16);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].kind, BehaviorEventKind::FileModify));
    }
}

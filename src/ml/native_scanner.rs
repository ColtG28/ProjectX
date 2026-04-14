use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crossbeam_channel::{bounded, Receiver, Sender};
use serde::Serialize;

use super::portable_features::FEATURE_COUNT;
use super::portable_model::PortableModel;

#[derive(Debug, Clone)]
pub struct NativeScanConfig {
    pub model_path: Option<PathBuf>,
    pub inputs: Vec<PathBuf>,
    pub output_prefix: PathBuf,
    pub batch_size: usize,
    pub concurrency: usize,
    pub max_files: usize,
    pub max_input_bytes: Option<usize>,
    pub evaluation_manifest: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub path: String,
    pub file_kind: &'static str,
    pub label: &'static str,
    pub score: f32,
    pub confidence: f32,
    pub file_size_bytes: u64,
    pub bytes_examined: usize,
    pub truncated_input: bool,
    pub worker_id: usize,
    pub batch_id: usize,
    pub duration_ms: u128,
    pub error: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluationMetrics {
    pub manifest_rows: usize,
    pub matched_rows: usize,
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1_score: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub model_source: String,
    pub output_csv: String,
    pub output_jsonl: String,
    pub runtime_seconds: f64,
    pub files_per_second: f64,
    pub peak_memory_bytes: Option<u64>,
    pub processed_files: usize,
    pub clean_files: usize,
    pub suspicious_files: usize,
    pub malicious_files: usize,
    pub error_files: usize,
    pub bytes_scanned: u64,
    pub concurrency: usize,
    pub batch_size: usize,
    pub feature_count: usize,
    pub evaluation: Option<EvaluationMetrics>,
}

#[derive(Debug, Clone)]
pub struct NativeScanOutput {
    pub summary: ScanSummary,
    pub summary_path: PathBuf,
    pub csv_path: PathBuf,
    pub jsonl_path: PathBuf,
}

#[derive(Debug, Clone)]
struct WorkItem {
    path: PathBuf,
}

#[derive(Debug)]
struct WorkBatch {
    items: Vec<WorkItem>,
}

#[derive(Debug, Default, Clone, Copy)]
struct EvaluationAccumulator {
    matched_rows: usize,
    true_positive: usize,
    true_negative: usize,
    false_positive: usize,
    false_negative: usize,
}

struct WriterContext {
    csv_path: PathBuf,
    jsonl_path: PathBuf,
    summary_path: PathBuf,
    config: NativeScanConfig,
    feature_count: usize,
    model_source: String,
    started_at: Instant,
    evaluation_labels: Option<HashMap<String, u8>>,
}

enum WriterMessage {
    Records(Vec<ScanRecord>),
}

pub fn run(config: NativeScanConfig) -> Result<NativeScanOutput, String> {
    if config.inputs.is_empty() {
        return Err(
            "At least one input file or directory is required for native ML scanning.".to_string(),
        );
    }

    let (model, model_source) = match config.model_path.as_ref() {
        Some(path) => (PortableModel::load(path)?, path.display().to_string()),
        None => (
            PortableModel::embedded_default(),
            "embedded://projectx-native-model-v1".to_string(),
        ),
    };
    let model = Arc::new(model);
    if !model.schema_matches_runtime() {
        return Err(format!(
            "Model feature schema mismatch. Rust expects {} features and the model declares {}. Retrain/export the model using the Rust feature order.",
            FEATURE_COUNT,
            model.feature_count()
        ));
    }

    let max_input_bytes = config.max_input_bytes.unwrap_or(model.max_input_bytes);
    let batch_size = config.batch_size.max(1);
    let concurrency = config.concurrency.max(1);
    let output_prefix = normalize_output_prefix(&config.output_prefix);
    let csv_path = output_prefix.with_extension("csv");
    let jsonl_path = output_prefix.with_extension("jsonl");
    let summary_path = output_prefix.with_extension("summary.json");
    if let Some(parent) = csv_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create output directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let evaluation_labels = config
        .evaluation_manifest
        .as_ref()
        .map(|path| load_evaluation_manifest(path))
        .transpose()?;

    let started_at = Instant::now();
    let (work_tx, work_rx) = bounded::<WorkBatch>(concurrency * 2);
    let (writer_tx, writer_rx) = bounded::<WriterMessage>(concurrency * 2);

    let writer_handle = spawn_writer(
        writer_rx,
        WriterContext {
            csv_path: csv_path.clone(),
            jsonl_path: jsonl_path.clone(),
            summary_path: summary_path.clone(),
            config: config.clone(),
            feature_count: model.feature_count(),
            model_source,
            started_at,
            evaluation_labels,
        },
    );

    let producer_inputs = config.inputs.clone();
    let max_files = config.max_files;
    let producer_handle =
        thread::spawn(move || produce_work_items(&producer_inputs, max_files, batch_size, work_tx));

    let mut worker_handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        let worker_rx = work_rx.clone();
        let worker_tx = writer_tx.clone();
        let worker_model = Arc::clone(&model);
        let handle = thread::spawn(move || {
            worker_loop(
                worker_id,
                worker_rx,
                worker_tx,
                worker_model,
                max_input_bytes,
            )
        });
        worker_handles.push(handle);
    }
    drop(writer_tx);

    producer_handle
        .join()
        .map_err(|_| "Native scanner producer thread panicked.".to_string())??;

    for handle in worker_handles {
        handle
            .join()
            .map_err(|_| "Native scanner worker thread panicked.".to_string())??;
    }

    writer_handle
        .join()
        .map_err(|_| "Native scanner writer thread panicked.".to_string())?
}

fn normalize_output_prefix(path: &Path) -> PathBuf {
    if path.extension().is_some() {
        path.with_extension("")
    } else if path.is_dir() {
        path.join("ml_scan_results")
    } else {
        path.to_path_buf()
    }
}

fn produce_work_items(
    inputs: &[PathBuf],
    max_files: usize,
    batch_size: usize,
    work_tx: Sender<WorkBatch>,
) -> Result<(), String> {
    let mut stack = Vec::with_capacity(inputs.len());
    stack.extend(inputs.iter().rev().cloned());
    let mut produced = 0usize;
    let mut batch = Vec::with_capacity(batch_size);

    while let Some(path) = stack.pop() {
        if produced >= max_files {
            break;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            batch.push(WorkItem { path });
            produced += 1;
            if batch.len() == batch_size {
                work_tx
                    .send(WorkBatch {
                        items: std::mem::take(&mut batch),
                    })
                    .map_err(|_| "Worker channel closed before scan completed.".to_string())?;
                batch = Vec::with_capacity(batch_size);
            }
            continue;
        }
        if metadata.is_dir() {
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
        }
    }

    if !batch.is_empty() {
        work_tx
            .send(WorkBatch { items: batch })
            .map_err(|_| "Worker channel closed before scan completed.".to_string())?;
    }

    Ok(())
}

fn worker_loop(
    worker_id: usize,
    work_rx: Receiver<WorkBatch>,
    writer_tx: Sender<WriterMessage>,
    model: Arc<PortableModel>,
    max_input_bytes: usize,
) -> Result<(), String> {
    let mut batch_id = 0usize;

    while let Ok(batch) = work_rx.recv() {
        batch_id += 1;
        let records = process_batch(worker_id, batch_id, batch.items, &model, max_input_bytes);
        writer_tx
            .send(WriterMessage::Records(records))
            .map_err(|_| "Writer channel closed before results were flushed.".to_string())?;
    }

    Ok(())
}

fn process_batch(
    worker_id: usize,
    batch_id: usize,
    batch: Vec<WorkItem>,
    model: &PortableModel,
    max_input_bytes: usize,
) -> Vec<ScanRecord> {
    let mut records = Vec::with_capacity(batch.len());

    for item in batch {
        let started = Instant::now();
        match super::portable_features::extract_path(&item.path, max_input_bytes) {
            Ok(features) => {
                let prediction = model.predict(&features.values);
                records.push(ScanRecord {
                    path: item.path.display().to_string(),
                    file_kind: features.file_kind,
                    label: prediction.label,
                    score: prediction.score,
                    confidence: prediction.confidence,
                    file_size_bytes: features.file_size_bytes,
                    bytes_examined: features.bytes_examined,
                    truncated_input: features.truncated_input,
                    worker_id,
                    batch_id,
                    duration_ms: started.elapsed().as_millis(),
                    error: None,
                    warning: features.warning,
                });
            }
            Err(error) => records.push(ScanRecord {
                path: item.path.display().to_string(),
                file_kind: "error",
                label: "error",
                score: 0.0,
                confidence: 0.0,
                file_size_bytes: 0,
                bytes_examined: 0,
                truncated_input: false,
                worker_id,
                batch_id,
                duration_ms: started.elapsed().as_millis(),
                error: Some(error),
                warning: None,
            }),
        }
    }

    records
}

fn spawn_writer(
    writer_rx: Receiver<WriterMessage>,
    context: WriterContext,
) -> thread::JoinHandle<Result<NativeScanOutput, String>> {
    thread::spawn(move || {
        let WriterContext {
            csv_path,
            jsonl_path,
            summary_path,
            config,
            feature_count,
            model_source,
            started_at,
            evaluation_labels,
        } = context;
        let csv_file = File::create(&csv_path)
            .map_err(|error| format!("Failed to create {}: {error}", csv_path.display()))?;
        let jsonl_file = File::create(&jsonl_path)
            .map_err(|error| format!("Failed to create {}: {error}", jsonl_path.display()))?;
        let mut csv_writer = BufWriter::with_capacity(1 << 20, csv_file);
        let mut jsonl_writer = BufWriter::with_capacity(1 << 20, jsonl_file);

        writeln!(
            csv_writer,
            "path,file_kind,label,score,confidence,file_size_bytes,bytes_examined,truncated_input,worker_id,batch_id,duration_ms,error,warning"
        )
        .map_err(|error| format!("Failed to write CSV header: {error}"))?;

        let mut processed_files = 0usize;
        let mut clean_files = 0usize;
        let mut suspicious_files = 0usize;
        let mut malicious_files = 0usize;
        let mut error_files = 0usize;
        let mut bytes_scanned = 0u64;
        let mut peak_memory_bytes = current_memory_bytes();
        let mut evaluation = EvaluationAccumulator::default();
        let progress_interval = config.batch_size.max(1) * config.concurrency.max(1) * 4;

        for message in writer_rx {
            match message {
                WriterMessage::Records(records) => {
                    for record in records {
                        write_record_csv(&mut csv_writer, &record)?;
                        serde_json::to_writer(&mut jsonl_writer, &record)
                            .map_err(|error| format!("Failed to write JSONL record: {error}"))?;
                        writeln!(jsonl_writer)
                            .map_err(|error| format!("Failed to finalize JSONL line: {error}"))?;

                        processed_files += 1;
                        bytes_scanned += record.bytes_examined as u64;
                        match record.label {
                            "clean" => clean_files += 1,
                            "suspicious" => suspicious_files += 1,
                            "malicious" => malicious_files += 1,
                            _ => error_files += 1,
                        }

                        if let Some(labels) = evaluation_labels.as_ref() {
                            if let Some(expected) = labels.get(&record.path) {
                                evaluation.observe(*expected, record.label);
                            }
                        }
                    }

                    if processed_files != 0 && processed_files % progress_interval == 0 {
                        let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                        eprintln!(
                            "[native-ml] processed={} throughput={:.2} files/sec rss={} bytes",
                            processed_files,
                            processed_files as f64 / elapsed,
                            current_memory_bytes().unwrap_or(0)
                        );
                    }

                    if let Some(current) = current_memory_bytes() {
                        peak_memory_bytes = Some(peak_memory_bytes.unwrap_or(0).max(current));
                    }
                }
            }
        }

        csv_writer
            .flush()
            .map_err(|error| format!("Failed to flush CSV output: {error}"))?;
        jsonl_writer
            .flush()
            .map_err(|error| format!("Failed to flush JSONL output: {error}"))?;

        let runtime_seconds = started_at.elapsed().as_secs_f64();
        let files_per_second = if runtime_seconds > 0.0 {
            processed_files as f64 / runtime_seconds
        } else {
            0.0
        };

        let evaluation = evaluation_labels
            .as_ref()
            .map(|labels| compute_evaluation_metrics(labels.len(), evaluation));

        let summary = ScanSummary {
            model_source,
            output_csv: csv_path.display().to_string(),
            output_jsonl: jsonl_path.display().to_string(),
            runtime_seconds,
            files_per_second,
            peak_memory_bytes,
            processed_files,
            clean_files,
            suspicious_files,
            malicious_files,
            error_files,
            bytes_scanned,
            concurrency: config.concurrency,
            batch_size: config.batch_size,
            feature_count,
            evaluation,
        };

        let summary_json = serde_json::to_string_pretty(&summary)
            .map_err(|error| format!("Failed to serialize summary JSON: {error}"))?;
        fs::write(&summary_path, summary_json)
            .map_err(|error| format!("Failed to write {}: {error}", summary_path.display()))?;

        Ok(NativeScanOutput {
            summary,
            summary_path,
            csv_path,
            jsonl_path,
        })
    })
}

fn write_record_csv(writer: &mut BufWriter<File>, record: &ScanRecord) -> Result<(), String> {
    write_csv_field(writer, &record.path)?;
    writer.write_all(b",").map_err(csv_io_error)?;
    write_csv_field(writer, record.file_kind)?;
    writer.write_all(b",").map_err(csv_io_error)?;
    write_csv_field(writer, record.label)?;
    write!(
        writer,
        ",{:.6},{:.6},{},{},{},{},{},{},",
        record.score,
        record.confidence,
        record.file_size_bytes,
        record.bytes_examined,
        record.truncated_input,
        record.worker_id,
        record.batch_id,
        record.duration_ms
    )
    .map_err(csv_io_error)?;
    write_csv_field(writer, record.error.as_deref().unwrap_or_default())?;
    writer.write_all(b",").map_err(csv_io_error)?;
    write_csv_field(writer, record.warning.as_deref().unwrap_or_default())?;
    writer.write_all(b"\n").map_err(csv_io_error)?;
    Ok(())
}

fn write_csv_field(writer: &mut BufWriter<File>, value: &str) -> Result<(), String> {
    if !value.contains([',', '"', '\n']) {
        return writer.write_all(value.as_bytes()).map_err(csv_io_error);
    }

    writer.write_all(b"\"").map_err(csv_io_error)?;
    write_csv_escaped_inner(writer, value)?;
    writer.write_all(b"\"").map_err(csv_io_error)?;
    Ok(())
}

fn write_csv_escaped_inner(writer: &mut BufWriter<File>, value: &str) -> Result<(), String> {
    let mut start = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'"' {
            writer
                .write_all(&value.as_bytes()[start..index])
                .map_err(csv_io_error)?;
            writer.write_all(b"\"\"").map_err(csv_io_error)?;
            start = index + 1;
        }
    }
    writer
        .write_all(&value.as_bytes()[start..])
        .map_err(csv_io_error)
}

fn csv_io_error(error: std::io::Error) -> String {
    format!("Failed to write CSV record: {error}")
}

fn load_evaluation_manifest(path: &Path) -> Result<HashMap<String, u8>, String> {
    let file = File::open(path).map_err(|error| {
        format!(
            "Failed to open evaluation manifest {}: {error}",
            path.display()
        )
    })?;
    let reader = BufReader::new(file);
    let mut labels = HashMap::new();

    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "Failed to read evaluation manifest line {}: {error}",
                line_number + 1
            )
        })?;
        if line_number == 0 && line.to_ascii_lowercase().contains("path") && line.contains("label")
        {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let Some(path_part) = parts.next() else {
            continue;
        };
        let Some(label_part) = parts.next() else {
            return Err(format!(
                "Invalid evaluation manifest row {}. Expected: path,label",
                line_number + 1
            ));
        };
        let label = match label_part.trim() {
            "1" | "malicious" => 1,
            "0" | "clean" | "benign" => 0,
            other => {
                return Err(format!(
                    "Unsupported label '{}' on evaluation manifest line {}.",
                    other,
                    line_number + 1
                ))
            }
        };
        labels.insert(path_part.trim().to_string(), label);
    }

    Ok(labels)
}

fn compute_evaluation_metrics(
    manifest_rows: usize,
    rows: EvaluationAccumulator,
) -> EvaluationMetrics {
    let accuracy = safe_ratio(rows.true_positive + rows.true_negative, rows.matched_rows);
    let precision = safe_ratio(rows.true_positive, rows.true_positive + rows.false_positive);
    let recall = safe_ratio(rows.true_positive, rows.true_positive + rows.false_negative);
    let f1_score = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    EvaluationMetrics {
        manifest_rows,
        matched_rows: rows.matched_rows,
        accuracy,
        precision,
        recall,
        f1_score,
    }
}

fn safe_ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

fn current_memory_bytes() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if status != 0 {
            return None;
        }
        let usage = unsafe { usage.assume_init() };
        #[cfg(target_os = "macos")]
        {
            return Some(usage.ru_maxrss as u64);
        }
        #[cfg(not(target_os = "macos"))]
        {
            return Some((usage.ru_maxrss as u64) * 1024);
        }
    }

    #[allow(unreachable_code)]
    None
}

impl EvaluationAccumulator {
    fn observe(&mut self, expected: u8, label: &str) {
        let predicted = u8::from(label == "malicious" || label == "suspicious");
        self.matched_rows += 1;
        match (expected, predicted) {
            (1, 1) => self.true_positive += 1,
            (0, 0) => self.true_negative += 1,
            (0, 1) => self.false_positive += 1,
            (1, 0) => self.false_negative += 1,
            _ => {}
        }
    }
}


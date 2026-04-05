# ProjectX EMBER Benchmark

This directory now contains two distinct benchmark truths:

1. `REFERENCE_EMBER`
2. `PROJECTX_ADAPTED_PARITY_INVALID`
3. `PROJECTX_ADAPTED_PARITY_ACCEPTABLE`

They are not the same thing, and this README is intentionally explicit about that.

## What is currently valid

- EMBER archive download and extraction
- ProjectX ↔ EMBER schema comparison
- Adapter-based transformation from EMBER raw rows into a ProjectX-shaped 386-feature vector
- Python vs Rust portable-inference agreement testing on the adapted vectors
- Honest parity-aware benchmark execution that still produces usable outputs when parity is invalid

## What is not currently valid

- A claim that ProjectX has proven full Rust-parity on EMBER
- A claim that a 10k or 100k adapted benchmark is a valid Rust-runtime benchmark when parity is marked invalid
- A claim that EMBER evaluates host-side Rust binary extraction directly

Current real status from the latest artifacts:

- Rust/Python portable inference parity on adapted vectors: implementation-strong
- Schema coverage for adapted parity: insufficient
- Current recommendation: `parity invalid`

## Files

- `setup.sh`: create `.venv` and install local benchmark dependencies
- `download_data.sh`: download and verify EMBER archives
- `schema_mapping.py`: generate `schema_mapping.json` and `schema_mapping.md`
- `projectx_ember_schema.py`: shared schema and mapping definitions
- `projectx_ember_adapter.py`: convert EMBER raw rows into ProjectX-shaped feature vectors
- `parity_test.py`: compare Python and Rust portable inference on the adapted vectors
- `eval_projectx_parity.py`: strict scaled adapted evaluation gate
- `run_full_eval.py`: one-command honest benchmark runner with `latest/` outputs
- `prepare_vectorized.py`: optional upstream EMBER vectorization helper
- `preprocess.py`, `train_scanner.py`, `eval_scanner.py`: reference EMBER workflow pieces from the earlier benchmark path
- `run_benchmark.sh`: one-command schema-map + parity-gated benchmark runner

## Setup

```bash
cd /path/to/ProjectX
bash ember_benchmark/setup.sh
bash ember_benchmark/download_data.sh 2018 2
```

Dataset directory used by the parity pipeline:

```bash
ember_benchmark/data/raw/ember2018_v2/ember2018
```

## Run schema mapping

```bash
python3 ember_benchmark/schema_mapping.py
```

Outputs:

- `ember_benchmark/schema_mapping.json`
- `ember_benchmark/schema_mapping.md`

## Run the adapter

```bash
python3 ember_benchmark/projectx_ember_adapter.py \
  --dataset-dir ember_benchmark/data/raw/ember2018_v2/ember2018 \
  --sample-size 1000 \
  --seed 1337
```

Outputs:

- `ember_benchmark/artifacts/adapter_output.jsonl`
- `ember_benchmark/artifacts/adapter_summary.json`
- `ember_benchmark/artifacts/adapter_summary.md`

## Run the parity test

```bash
python3 ember_benchmark/parity_test.py \
  --dataset-dir ember_benchmark/data/raw/ember2018_v2/ember2018 \
  --sample-size 1000 \
  --seed 1337
```

Outputs:

- `ember_benchmark/artifacts/parity_test.json`
- `ember_benchmark/artifacts/parity_test.md`
- `ember_benchmark/artifacts/failure_analysis.json`
- `ember_benchmark/artifacts/failure_analysis.md`

## Run the next honest benchmark

```bash
bash ember_benchmark/run_benchmark.sh
```

This now does all of the following:

1. refreshes schema mapping
2. refreshes parity outputs
3. runs `REFERENCE_EMBER`
4. runs `PROJECTX_ADAPTED_PARITY_INVALID` or `PROJECTX_ADAPTED_PARITY_ACCEPTABLE`
5. writes consolidated outputs to `ember_benchmark/artifacts/latest/`

You can also call the Python runner directly:

```bash
python3 ember_benchmark/run_full_eval.py \
  --dataset-dir ember_benchmark/data/raw/ember2018_v2/ember2018 \
  --parity-sample-size 1000 \
  --sample-size 1000
```

Generated outputs in `ember_benchmark/artifacts/latest/`:

- `reference_ember.json`
- `reference_ember.md`
- `projectx_adapted.json`
- `projectx_adapted.md`
- `summary.json`
- `summary.md`
- `next_steps.json`
- `next_steps.md`
- copied prerequisite artifacts such as `adapter_summary.json`, `parity_test.json`, and `failure_analysis.json`

## Run strict scaled evaluation only when parity is acceptable

If `parity_test.json` says:

```json
{ "recommendation": "parity acceptable" }
```

then you may run:

```bash
python3 ember_benchmark/eval_projectx_parity.py \
  --dataset-dir ember_benchmark/data/raw/ember2018_v2/ember2018 \
  --sample-size 10000
```

## How to interpret parity validity

- `parity acceptable`
  Rust portable inference agrees with Python portable inference, and adapter/schema risk is low enough to permit a scaled adapted benchmark.
- `parity weak`
  Inference agreement or schema coverage is not strong enough for confident scaled claims.
- `parity invalid`
  Do not treat the adapted benchmark as Rust-parity. Use it only as a diagnostic bridge, and label reports `PROJECTX_ADAPTED_PARITY_INVALID`.

## What result is currently the most trustworthy

- `REFERENCE_EMBER` is currently the most trustworthy benchmark output.
- `PROJECTX_ADAPTED_PARITY_INVALID` is still useful for scanner diagnostics and roadmap planning, but not for claiming Rust-parity.

## Next recommended benchmark

Run:

```bash
bash ember_benchmark/run_benchmark.sh
```

Then use:

- `ember_benchmark/artifacts/latest/reference_ember.json` as the cleanest benchmark baseline
- `ember_benchmark/artifacts/latest/projectx_adapted.json` as the current adapted ProjectX result
- `ember_benchmark/artifacts/latest/next_steps.md` as the prioritized scanner-improvement roadmap

## Current blocking gaps

The present adapter still leaves these major risks:

- `string_pattern_*` features are currently approximated from EMBER-visible imports, exports, section names, and coarse string counters
- `pe_entrypoint_ratio` is currently approximated from entry-section order and virtual sizes
- `pe_overlay_ratio` is currently approximated from file size vs headers plus section raw sizes
- `dos_stub_contains_message` is unrecoverable from EMBER raw rows
- `longest_printable_run_ratio` and `max_string_len_log2` remain unrecoverable from EMBER raw rows
- `pe_header_anomaly_score` and some import semantics remain approximate
- high coverage alone is not enough for parity: approximation density must also be low enough before the benchmark can be labeled `PROJECTX_ADAPTED_PARITY_ACCEPTABLE`

Until those gaps are reduced enough for parity to become acceptable, the benchmark should remain labeled `NOT Rust-parity`.

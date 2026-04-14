use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::portable_features::{FEATURE_COUNT, FEATURE_NAMES};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableModel {
    #[serde(default = "default_model_type")]
    pub model_type: String,
    #[serde(default)]
    pub version: String,
    pub feature_names: Box<[String]>,
    pub weights: Box<[f32]>,
    #[serde(default)]
    pub intercept: f32,
    #[serde(default = "default_malicious_threshold")]
    pub malicious_threshold: f32,
    #[serde(default = "default_suspicious_threshold")]
    pub suspicious_threshold: f32,
    #[serde(default = "default_max_input_bytes")]
    pub max_input_bytes: usize,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub calibration: Option<CalibrationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationConfig {
    pub method: String,
    #[serde(default)]
    pub a: Option<f32>,
    #[serde(default)]
    pub b: Option<f32>,
    #[serde(default)]
    pub x: Option<Vec<f32>>,
    #[serde(default)]
    pub y: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Prediction {
    pub score: f32,
    pub confidence: f32,
    pub label: &'static str,
}

fn default_model_type() -> String {
    "portable-linear-v1".to_string()
}

fn default_malicious_threshold() -> f32 {
    0.75
}

fn default_suspicious_threshold() -> f32 {
    0.45
}

fn default_max_input_bytes() -> usize {
    32 * 1024 * 1024
}

impl PortableModel {
    pub fn embedded_default() -> Self {
        Self {
            model_type: "portable-linear-v1".to_string(),
            version: "projectx-embedded-v1".to_string(),
            feature_names: FEATURE_NAMES
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            weights: EMBEDDED_WEIGHTS.to_vec().into_boxed_slice(),
            intercept: -3.4,
            malicious_threshold: 0.5,
            suspicious_threshold: 0.4,
            max_input_bytes: 32 * 1024 * 1024,
            notes: None,
            calibration: None,
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|error| format!("Failed to read model file {}: {error}", path.display()))?;
        let model: Self = serde_json::from_str(&raw)
            .map_err(|error| format!("Failed to parse model file {}: {error}", path.display()))?;
        model.validate()?;
        Ok(model)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.model_type != "portable-linear-v1" {
            return Err(format!(
                "Unsupported model type '{}'. Expected portable-linear-v1.",
                self.model_type
            ));
        }
        if self.feature_names.is_empty() {
            return Err("Model feature_names must not be empty.".to_string());
        }
        if self.feature_names.len() != self.weights.len() {
            return Err(format!(
                "Model feature count mismatch: {} feature names vs {} weights.",
                self.feature_names.len(),
                self.weights.len()
            ));
        }
        if !(0.0..=1.0).contains(&self.suspicious_threshold)
            || !(0.0..=1.0).contains(&self.malicious_threshold)
        {
            return Err("Model thresholds must be between 0.0 and 1.0.".to_string());
        }
        if self.suspicious_threshold > self.malicious_threshold {
            return Err(
                "suspicious_threshold cannot be greater than malicious_threshold.".to_string(),
            );
        }
        if self.max_input_bytes == 0 {
            return Err("max_input_bytes must be greater than zero.".to_string());
        }
        if let Some(calibration) = &self.calibration {
            calibration.validate()?;
        }
        Ok(())
    }

    pub fn feature_count(&self) -> usize {
        self.feature_names.len()
    }

    pub fn predict_score(&self, features: &[f32; FEATURE_COUNT]) -> f32 {
        let linear = self
            .weights
            .iter()
            .zip(features.iter())
            .fold(self.intercept, |acc, (weight, value)| {
                acc + (weight * value)
            });
        let raw_score = sigmoid(linear);
        self.apply_calibration(raw_score)
    }

    pub fn predict(&self, features: &[f32; FEATURE_COUNT]) -> Prediction {
        let score = self.predict_score(features);
        self.classify(score)
    }

    pub fn predict_slice(&self, features: &[f32]) -> Result<Prediction, String> {
        if features.len() != FEATURE_COUNT {
            return Err(format!(
                "Feature vector length mismatch. Expected {} values and received {}.",
                FEATURE_COUNT,
                features.len()
            ));
        }
        let mut values = [0.0f32; FEATURE_COUNT];
        values.copy_from_slice(features);
        Ok(self.predict(&values))
    }

    fn classify(&self, score: f32) -> Prediction {
        let label = if score >= self.malicious_threshold {
            "malicious"
        } else if score >= self.suspicious_threshold {
            "suspicious"
        } else {
            "clean"
        };

        let confidence = match label {
            "malicious" => score,
            "clean" => 1.0 - score,
            _ => 0.5 + (score - 0.5).abs(),
        }
        .clamp(0.0, 1.0);

        Prediction {
            score,
            confidence,
            label,
        }
    }

    fn apply_calibration(&self, score: f32) -> f32 {
        match &self.calibration {
            Some(calibration) => calibration.apply(score),
            None => score,
        }
    }

    pub fn schema_matches_runtime(&self) -> bool {
        self.weights.len() == FEATURE_COUNT
            && self
                .feature_names
                .iter()
                .map(String::as_str)
                .eq(FEATURE_NAMES.iter().copied())
    }
}

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        let exp = (-value).exp();
        1.0 / (1.0 + exp)
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

impl CalibrationConfig {
    fn validate(&self) -> Result<(), String> {
        match self.method.as_str() {
            "platt" => Ok(()),
            "isotonic" => {
                let x = self
                    .x
                    .as_ref()
                    .ok_or_else(|| "Isotonic calibration missing x breakpoints.".to_string())?;
                let y = self
                    .y
                    .as_ref()
                    .ok_or_else(|| "Isotonic calibration missing y values.".to_string())?;
                if x.len() != y.len() || x.is_empty() {
                    return Err(
                        "Isotonic calibration requires equal non-empty x/y arrays.".to_string()
                    );
                }
                Ok(())
            }
            other => Err(format!("Unsupported calibration method '{}'.", other)),
        }
    }

    fn apply(&self, score: f32) -> f32 {
        let clipped = score.clamp(1e-6, 1.0 - 1e-6);
        match self.method.as_str() {
            "platt" => {
                let a = self.a.unwrap_or(1.0);
                let b = self.b.unwrap_or(0.0);
                sigmoid((a * clipped) + b)
            }
            "isotonic" => self.apply_isotonic(clipped),
            _ => clipped,
        }
    }

    fn apply_isotonic(&self, score: f32) -> f32 {
        let Some(x) = &self.x else {
            return score;
        };
        let Some(y) = &self.y else {
            return score;
        };
        if x.is_empty() || y.is_empty() || x.len() != y.len() {
            return score;
        }
        if score <= x[0] {
            return y[0].clamp(0.0, 1.0);
        }
        if score >= x[x.len() - 1] {
            return y[y.len() - 1].clamp(0.0, 1.0);
        }

        let index = x.partition_point(|value| *value < score);
        if index == 0 || index >= x.len() {
            return y[index.min(y.len() - 1)].clamp(0.0, 1.0);
        }
        let x0 = x[index - 1];
        let x1 = x[index];
        let y0 = y[index - 1];
        let y1 = y[index];
        if (x1 - x0).abs() < f32::EPSILON {
            return y1.clamp(0.0, 1.0);
        }
        let fraction = (score - x0) / (x1 - x0);
        (y0 + ((y1 - y0) * fraction)).clamp(0.0, 1.0)
    }
}

const EMBEDDED_WEIGHTS: [f32; 386] = [
    0.03, 0.02, 0.20, 0.35, 0.15, 0.10, -0.30, -0.25, 0.18, -0.12, 0.05, 0.01, 0.03, 0.45, 0.18,
    0.80, 0.10, 0.20, 0.02, 0.08, 0.03, 0.14, 0.18, 0.22, 1.20, 0.03, 0.04, 0.06, 0.04, 0.18,
    -0.05, 0.30, 0.30, 0.10, 0.02, 0.70, 0.90, 0.05, 0.02, 0.03, 0.04, 0.05, 0.00, 0.00, 0.00,
    0.00, 0.00, 0.00, 0.02, 0.02, 0.03, 0.03, 0.04, 0.04, 0.05, 0.05, 0.05, 0.05, 0.06, 0.06, 0.06,
    0.06, 0.07, 0.07, 0.07, 0.07, 0.08, 0.08, 0.08, 0.08, 0.09, 0.09, 0.10, 0.10, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0,
];

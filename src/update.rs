use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_OWNER: &str = "ColtG-28";
const DEFAULT_REPO: &str = "ProjectX";
const API_BASE: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";
const UPDATE_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_CACHE_ATTEMPTS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UpdateStatusKind {
    UpToDate,
    UpdateAvailable,
    #[default]
    Unknown,
    Error,
    Offline,
    RateLimited,
}

impl UpdateStatusKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::UpdateAvailable => "update_available",
            Self::Unknown => "unknown",
            Self::Error => "error",
            Self::Offline => "offline",
            Self::RateLimited => "rate_limited",
        }
    }

    pub fn user_label(self) -> &'static str {
        match self {
            Self::UpToDate => "Up to date",
            Self::UpdateAvailable => "Update available",
            Self::Unknown => "Status unknown",
            Self::Error => "Check failed",
            Self::Offline => "Offline",
            Self::RateLimited => "Rate limited",
        }
    }

    pub fn user_summary(self) -> &'static str {
        match self {
            Self::UpToDate => "This install matches the newest stable release we could confirm.",
            Self::UpdateAvailable => "A newer stable release is available for this device.",
            Self::Unknown => "ProjectX has not confirmed update status yet.",
            Self::Error => "GitHub release metadata could not be verified cleanly.",
            Self::Offline => "GitHub could not be reached during the most recent check.",
            Self::RateLimited => {
                "GitHub temporarily refused more checks because the API limit was reached."
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: String,
    pub tag_name: String,
    pub published_at: String,
    pub html_url: String,
    pub body: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_content_type: String,
    pub asset_match_reason: String,
    pub checksum_asset_name: Option<String>,
    pub checksum_asset_url: Option<String>,
    pub expected_sha256: Option<String>,
    pub checksum_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAttempt {
    pub checked_epoch: u64,
    pub status_kind: UpdateStatusKind,
    pub error: Option<String>,
    pub latest_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCache {
    pub owner: String,
    pub repo: String,
    pub include_prereleases: bool,
    pub last_attempt_epoch: u64,
    pub last_successful_check_epoch: u64,
    pub last_status_kind: UpdateStatusKind,
    pub last_error: Option<String>,
    pub latest_release: Option<ReleaseInfo>,
    pub recent_attempts: Vec<CachedAttempt>,
    #[serde(default)]
    pub last_automatic_check_epoch: u64,
    #[serde(default)]
    pub last_downloaded_version: Option<String>,
    #[serde(default)]
    pub last_downloaded_asset_name: Option<String>,
    #[serde(default)]
    pub last_downloaded_asset_path: Option<String>,
    #[serde(default)]
    pub last_download_epoch: u64,
    #[serde(default)]
    pub last_download_status: Option<String>,
    #[serde(default)]
    pub last_install_status: Option<String>,
    #[serde(default)]
    pub last_install_attempt_epoch: u64,
    #[serde(default)]
    pub restart_required_after_install: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateCheckReport {
    pub current_version: String,
    pub latest_release: Option<ReleaseInfo>,
    pub available_update: Option<ReleaseInfo>,
    pub last_checked_epoch: u64,
    pub last_successful_check_epoch: u64,
    pub status_kind: UpdateStatusKind,
    pub status_label: String,
    pub last_error: Option<String>,
    pub repo_label: String,
    pub release_page_url: String,
    pub used_cached_release: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CachedUpdateUiState {
    pub last_automatic_check_epoch: u64,
    pub last_downloaded_version: Option<String>,
    pub last_downloaded_asset_path: Option<String>,
    pub last_download_epoch: u64,
    pub last_download_status: Option<String>,
    pub last_install_status: Option<String>,
    pub last_install_attempt_epoch: u64,
    pub restart_required_after_install: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubReleaseConfig {
    pub owner: String,
    pub repo: String,
    pub token: Option<String>,
    pub include_prereleases: bool,
}

#[derive(Debug, Clone)]
enum FetchFailure {
    Offline(String),
    RateLimited(String),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetOs {
    MacOs,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetArch {
    X86_64,
    Aarch64,
    Other,
}

#[derive(Debug, Clone)]
struct ReleaseCandidate {
    version: ParsedVersion,
    published_at: String,
    release: ReleaseInfo,
}

#[derive(Debug, Clone)]
struct AssetSelection {
    asset: GitHubAsset,
    reason: String,
}

#[derive(Debug, Clone)]
enum AssetSelectionOutcome {
    Selected(AssetSelection),
    Ambiguous(String),
    Missing(String),
}

#[derive(Debug, Clone)]
struct ParsedVersion {
    normalized: String,
    numeric_parts: Vec<u64>,
    prerelease: Vec<PreIdentifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreIdentifier {
    Numeric(u64),
    Text(String),
}

pub fn check_for_updates(now_epoch: u64) -> UpdateCheckReport {
    let config = github_release_config();
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let cached = load_update_cache();

    match build_client().and_then(|client| fetch_release(&client, &config)) {
        Ok(release) => {
            let report = build_success_report(&config, current_version, release, now_epoch, false);
            let _ = save_update_cache(&config, &report, now_epoch);
            report
        }
        Err(failure) => {
            let report = build_failure_report(&config, current_version, now_epoch, failure, cached);
            let _ = save_update_cache(&config, &report, now_epoch);
            report
        }
    }
}

pub fn github_release_config() -> GitHubReleaseConfig {
    github_release_config_from_env_map(&std::env::vars().collect::<HashMap<_, _>>())
}

pub fn releases_page_url(owner: &str, repo: &str) -> String {
    format!("https://github.com/{owner}/{repo}/releases")
}

pub fn verify_downloaded_asset(path: &Path, expected_sha256: &str) -> Result<String, String> {
    let expected = normalize_sha256(expected_sha256)
        .ok_or_else(|| "The expected SHA-256 value is malformed.".to_string())?;
    let actual = sha256_file(path)?;
    if actual.eq_ignore_ascii_case(&expected) {
        Ok(format!(
            "SHA-256 verified successfully for {}.",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("selected file")
        ))
    } else {
        Err(format!(
            "SHA-256 verification failed. Expected {expected}, got {actual}."
        ))
    }
}

pub fn load_cached_update_ui_state() -> Option<CachedUpdateUiState> {
    let cache = load_update_cache()?;
    Some(CachedUpdateUiState {
        last_automatic_check_epoch: cache.last_automatic_check_epoch,
        last_downloaded_version: cache.last_downloaded_version,
        last_downloaded_asset_path: cache.last_downloaded_asset_path,
        last_download_epoch: cache.last_download_epoch,
        last_download_status: cache.last_download_status,
        last_install_status: cache.last_install_status,
        last_install_attempt_epoch: cache.last_install_attempt_epoch,
        restart_required_after_install: cache.restart_required_after_install,
    })
}

pub fn persist_automatic_check_epoch(now_epoch: u64) -> Result<(), String> {
    mutate_update_cache(|cache| {
        cache.last_automatic_check_epoch = now_epoch;
    })
}

pub fn persist_download_result(
    version: Option<&str>,
    asset_name: Option<&str>,
    asset_path: Option<&Path>,
    status: &str,
    now_epoch: u64,
) -> Result<(), String> {
    mutate_update_cache(|cache| {
        cache.last_downloaded_version = version.map(str::to_string);
        cache.last_downloaded_asset_name = asset_name.map(str::to_string);
        cache.last_downloaded_asset_path =
            asset_path.map(|path| path.to_string_lossy().to_string());
        cache.last_download_epoch = now_epoch;
        cache.last_download_status = Some(status.to_string());
    })
}

pub fn persist_install_result(
    status: &str,
    now_epoch: u64,
    restart_required_after_install: bool,
) -> Result<(), String> {
    mutate_update_cache(|cache| {
        cache.last_install_status = Some(status.to_string());
        cache.last_install_attempt_epoch = now_epoch;
        cache.restart_required_after_install = restart_required_after_install;
    })
}

pub fn download_release_asset<F>(
    asset_url: &str,
    asset_name: &str,
    mut on_progress: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(u64, Option<u64>),
{
    let config = github_release_config();
    let client = build_client().map_err(fetch_failure_message)?;
    let mut response = apply_request_headers(client.get(asset_url), &config)
        .send()
        .map_err(classify_request_error)
        .map_err(fetch_failure_message)?;
    if !response.status().is_success() {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .text()
            .unwrap_or_else(|_| "Failed to read GitHub response body.".to_string());
        return Err(fetch_failure_message(classify_http_failure(
            status, &headers, &body,
        )));
    }

    let total = response.content_length();
    let output_dir = crate::app_paths::update_download_dir();
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("Failed to create update-download directory: {error}"))?;
    let output_path = unique_download_path(&output_dir, asset_name);
    let mut file = fs::File::create(&output_path)
        .map_err(|error| format!("Failed to create {}: {error}", output_path.display()))?;
    let mut downloaded = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|error| format!("Failed to read release download: {error}"))?;
        if read == 0 {
            break;
        }
        std::io::Write::write_all(&mut file, &buffer[..read])
            .map_err(|error| format!("Failed to write {}: {error}", output_path.display()))?;
        downloaded = downloaded.saturating_add(read as u64);
        on_progress(downloaded, total);
    }
    Ok(output_path)
}

pub fn compare_versions(left: &str, right: &str) -> Ordering {
    compare_parsed_versions(&parse_version(left), &parse_version(right))
}

pub fn is_version_newer(candidate: &str, current: &str) -> bool {
    compare_versions(candidate, current).is_gt()
}

pub fn normalize_version_label(version: &str) -> String {
    let trimmed = version.trim();
    let start = trimmed
        .char_indices()
        .find_map(|(index, ch)| ch.is_ascii_digit().then_some(index))
        .unwrap_or(trimmed.len());
    trimmed[start..]
        .split('+')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn github_release_config_from_env_map(env_map: &HashMap<String, String>) -> GitHubReleaseConfig {
    GitHubReleaseConfig {
        owner: env_value(env_map, "PROJECTX_GITHUB_OWNER")
            .unwrap_or(DEFAULT_OWNER)
            .to_string(),
        repo: env_value(env_map, "PROJECTX_GITHUB_REPO")
            .unwrap_or(DEFAULT_REPO)
            .to_string(),
        token: env_value(env_map, "PROJECTX_GITHUB_TOKEN").map(str::to_string),
        include_prereleases: env_value(env_map, "PROJECTX_INCLUDE_PRERELEASES")
            .map(parse_env_bool)
            .unwrap_or(false),
    }
}

fn build_success_report(
    config: &GitHubReleaseConfig,
    current_version: String,
    release: ReleaseInfo,
    now_epoch: u64,
    used_cached_release: bool,
) -> UpdateCheckReport {
    let has_update = is_version_newer(&release.version, &current_version);
    let status_kind = if has_update {
        UpdateStatusKind::UpdateAvailable
    } else {
        UpdateStatusKind::UpToDate
    };
    let status_label = if has_update {
        format!("Update {} is available.", release.version)
    } else {
        format!("ProjectX is up to date ({current_version}).")
    };

    UpdateCheckReport {
        current_version,
        latest_release: Some(release.clone()),
        available_update: has_update.then_some(release),
        last_checked_epoch: now_epoch,
        last_successful_check_epoch: now_epoch,
        status_kind,
        status_label,
        last_error: None,
        repo_label: format!("{}/{}", config.owner, config.repo),
        release_page_url: releases_page_url(&config.owner, &config.repo),
        used_cached_release,
    }
}

fn build_failure_report(
    config: &GitHubReleaseConfig,
    current_version: String,
    now_epoch: u64,
    failure: FetchFailure,
    cached: Option<UpdateCache>,
) -> UpdateCheckReport {
    let (status_kind, error_message) = match failure {
        FetchFailure::Offline(message) => (UpdateStatusKind::Offline, message),
        FetchFailure::RateLimited(message) => (UpdateStatusKind::RateLimited, message),
        FetchFailure::Error(message) => (UpdateStatusKind::Error, message),
    };

    let cached_release = cached
        .filter(|cache| cache.owner == config.owner && cache.repo == config.repo)
        .and_then(|cache| cache.latest_release.clone().map(|release| (cache, release)));

    if let Some((cache, release)) = cached_release {
        let has_update = is_version_newer(&release.version, &current_version);
        return UpdateCheckReport {
            current_version,
            latest_release: Some(release.clone()),
            available_update: has_update.then_some(release),
            last_checked_epoch: now_epoch,
            last_successful_check_epoch: cache.last_successful_check_epoch,
            status_kind,
            status_label: format!(
                "{}. Showing cached release metadata from {}.",
                status_prefix(status_kind),
                cache.last_successful_check_epoch
            ),
            last_error: Some(error_message),
            repo_label: format!("{}/{}", config.owner, config.repo),
            release_page_url: releases_page_url(&config.owner, &config.repo),
            used_cached_release: true,
        };
    }

    UpdateCheckReport {
        current_version,
        latest_release: None,
        available_update: None,
        last_checked_epoch: now_epoch,
        last_successful_check_epoch: 0,
        status_kind,
        status_label: status_prefix(status_kind).to_string(),
        last_error: Some(error_message),
        repo_label: format!("{}/{}", config.owner, config.repo),
        release_page_url: releases_page_url(&config.owner, &config.repo),
        used_cached_release: false,
    }
}

fn status_prefix(kind: UpdateStatusKind) -> &'static str {
    match kind {
        UpdateStatusKind::Offline => "GitHub could not be reached",
        UpdateStatusKind::RateLimited => "GitHub API rate limit was reached",
        UpdateStatusKind::Error => "The GitHub release check failed",
        _ => "Update status is unknown",
    }
}

fn build_client() -> Result<Client, FetchFailure> {
    Client::builder()
        .timeout(UPDATE_TIMEOUT)
        .build()
        .map_err(|error| FetchFailure::Error(format!("Failed to build update client: {error}")))
}

fn fetch_release(
    client: &Client,
    config: &GitHubReleaseConfig,
) -> Result<ReleaseInfo, FetchFailure> {
    let url = format!(
        "{API_BASE}/repos/{}/{}/releases?per_page=30",
        config.owner, config.repo
    );
    let response = apply_request_headers(client.get(url), config)
        .send()
        .map_err(classify_request_error)?;
    let status = response.status();
    let headers = response.headers().clone();
    let text = response
        .text()
        .map_err(|error| FetchFailure::Error(format!("Failed to read GitHub response: {error}")))?;

    if !status.is_success() {
        return Err(classify_http_failure(status, &headers, &text));
    }

    let releases = serde_json::from_str::<Vec<GitHubRelease>>(&text).map_err(|error| {
        FetchFailure::Error(format!("Failed to parse GitHub releases response: {error}"))
    })?;

    select_release(client, config, &releases)
}

fn apply_request_headers(builder: RequestBuilder, config: &GitHubReleaseConfig) -> RequestBuilder {
    let builder = builder
        .header(
            USER_AGENT,
            format!("ProjectX-Updater/{}", env!("CARGO_PKG_VERSION")),
        )
        .header(ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION);

    if let Some(token) = config.token.as_deref() {
        builder.header(AUTHORIZATION, format!("Bearer {token}"))
    } else {
        builder
    }
}

fn classify_request_error(error: reqwest::Error) -> FetchFailure {
    if error.is_timeout() || error.is_connect() {
        FetchFailure::Offline(format!("GitHub could not be reached: {error}"))
    } else {
        FetchFailure::Error(format!("GitHub request failed: {error}"))
    }
}

fn classify_http_failure(
    status: reqwest::StatusCode,
    headers: &HeaderMap,
    body: &str,
) -> FetchFailure {
    if status == reqwest::StatusCode::FORBIDDEN
        && headers
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            == Some("0")
    {
        return FetchFailure::RateLimited(
            "GitHub API rate limit exceeded. Try again later or configure PROJECTX_GITHUB_TOKEN."
                .to_string(),
        );
    }

    if status == reqwest::StatusCode::UNAUTHORIZED {
        return FetchFailure::Error(
            "GitHub rejected the configured token. Check PROJECTX_GITHUB_TOKEN.".to_string(),
        );
    }

    if status == reqwest::StatusCode::NOT_FOUND {
        return FetchFailure::Error(
            "GitHub repository or releases endpoint was not found. Check PROJECTX_GITHUB_OWNER and PROJECTX_GITHUB_REPO."
                .to_string(),
        );
    }

    if status == reqwest::StatusCode::FORBIDDEN && body.to_ascii_lowercase().contains("rate limit")
    {
        return FetchFailure::RateLimited(
            "GitHub API rate limit exceeded. Try again later or configure PROJECTX_GITHUB_TOKEN."
                .to_string(),
        );
    }

    FetchFailure::Error(format!("GitHub Releases returned HTTP {}.", status))
}

fn select_release(
    client: &Client,
    config: &GitHubReleaseConfig,
    releases: &[GitHubRelease],
) -> Result<ReleaseInfo, FetchFailure> {
    let mut candidates = Vec::new();
    let mut selection_failures = Vec::new();

    for release in releases
        .iter()
        .filter(|release| !release.draft)
        .filter(|release| config.include_prereleases || !release.prerelease)
    {
        let Some(parsed_version) = parse_version_option(&release.tag_name) else {
            continue;
        };

        match select_platform_asset(&release.assets) {
            AssetSelectionOutcome::Selected(selection) => {
                let checksum =
                    resolve_checksum_for_asset(client, config, &selection.asset, &release.assets)?;
                candidates.push(ReleaseCandidate {
                    version: parsed_version.clone(),
                    published_at: release
                        .published_at
                        .clone()
                        .or_else(|| release.created_at.clone())
                        .unwrap_or_default(),
                    release: ReleaseInfo {
                        version: parsed_version.normalized.clone(),
                        tag_name: release.tag_name.trim().to_string(),
                        published_at: release
                            .published_at
                            .clone()
                            .or_else(|| release.created_at.clone())
                            .unwrap_or_default(),
                        html_url: release.html_url.clone(),
                        body: release.body.clone().unwrap_or_default(),
                        asset_name: selection.asset.name.clone(),
                        asset_url: selection.asset.browser_download_url.clone(),
                        asset_content_type: selection.asset.content_type.clone(),
                        asset_match_reason: selection.reason,
                        checksum_asset_name: checksum.asset_name,
                        checksum_asset_url: checksum.asset_url,
                        expected_sha256: checksum.sha256,
                        checksum_status: checksum.status,
                    },
                });
            }
            AssetSelectionOutcome::Ambiguous(reason) | AssetSelectionOutcome::Missing(reason) => {
                selection_failures.push(format!("{}: {}", release.tag_name.trim(), reason));
            }
        }
    }

    candidates.sort_by(|left, right| compare_release_candidates(right, left));
    candidates
        .into_iter()
        .next()
        .map(|candidate| candidate.release)
        .ok_or_else(|| {
            let mut message =
                "No suitable published release asset was found for this platform.".to_string();
            if !selection_failures.is_empty() {
                message.push(' ');
                message.push_str(&selection_failures.join(" | "));
            }
            FetchFailure::Error(message)
        })
}

fn compare_release_candidates(left: &ReleaseCandidate, right: &ReleaseCandidate) -> Ordering {
    compare_parsed_versions(&left.version, &right.version)
        .then_with(|| left.published_at.cmp(&right.published_at))
}

fn select_platform_asset(assets: &[GitHubAsset]) -> AssetSelectionOutcome {
    let target_os = current_target_os();
    let target_arch = current_target_arch();
    let candidates = assets
        .iter()
        .filter(|asset| !is_checksum_asset_name(&asset.name))
        .filter_map(|asset| score_asset(asset, target_os, target_arch))
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return AssetSelectionOutcome::Missing(format!(
            "no asset matched {} {}",
            target_os.label(),
            target_arch.label()
        ));
    }

    let mut candidates = candidates;
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.asset.name.cmp(&right.asset.name))
    });

    let best = &candidates[0];
    if candidates
        .get(1)
        .is_some_and(|other| other.score == best.score)
    {
        let tied = candidates
            .iter()
            .take_while(|candidate| candidate.score == best.score)
            .map(|candidate| candidate.asset.name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        return AssetSelectionOutcome::Ambiguous(format!(
            "multiple assets matched equally well: {tied}"
        ));
    }

    AssetSelectionOutcome::Selected(AssetSelection {
        asset: best.asset.clone(),
        reason: best.reason.clone(),
    })
}

fn score_asset(
    asset: &GitHubAsset,
    target_os: TargetOs,
    target_arch: TargetArch,
) -> Option<ScoredAsset> {
    let name = asset.name.to_ascii_lowercase();
    let ext = detect_asset_extension(&name)?;
    let mut score = package_score(target_os, ext)?;
    let mut reasons = vec![format!("package {}", ext.label())];

    match os_hint_score(&name, target_os) {
        OsHint::Match(label) => {
            score += 60;
            reasons.push(format!("os {label}"));
        }
        OsHint::Conflict(_label) => return None,
        OsHint::Unknown => {}
    }

    match arch_hint_score(&name, target_arch) {
        ArchHint::Match(label) => {
            score += 25;
            reasons.push(format!("arch {label}"));
        }
        ArchHint::Conflict(_label) => return None,
        ArchHint::Unknown => {}
    }

    if name.contains("projectx") {
        score += 8;
        reasons.push("project name".to_string());
    }
    if asset
        .content_type
        .to_ascii_lowercase()
        .contains(ext.content_type_hint())
    {
        score += 4;
        reasons.push("content-type hint".to_string());
    }

    Some(ScoredAsset {
        asset: asset.clone(),
        score,
        reason: reasons.join(", "),
    })
}

fn resolve_checksum_for_asset(
    client: &Client,
    config: &GitHubReleaseConfig,
    asset: &GitHubAsset,
    assets: &[GitHubAsset],
) -> Result<ChecksumResolution, FetchFailure> {
    let matching = assets
        .iter()
        .filter(|candidate| is_checksum_asset_name(&candidate.name))
        .filter(|candidate| checksum_matches_asset_name(&candidate.name, &asset.name))
        .collect::<Vec<_>>();

    let checksum_asset = match matching.as_slice() {
        [] => {
            return Ok(ChecksumResolution {
                asset_name: None,
                asset_url: None,
                sha256: None,
                status: "No matching SHA-256 asset was published for this release.".to_string(),
            })
        }
        [single] => (*single).clone(),
        many => {
            return Ok(ChecksumResolution {
                asset_name: None,
                asset_url: None,
                sha256: None,
                status: format!(
                "Checksum verification is ambiguous because multiple checksum assets matched: {}",
                many.iter()
                    .map(|asset| asset.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            })
        }
    };

    let text = apply_request_headers(client.get(&checksum_asset.browser_download_url), config)
        .send()
        .map_err(classify_request_error)?
        .text()
        .map_err(|error| {
            FetchFailure::Error(format!(
                "Failed to read checksum asset {}: {error}",
                checksum_asset.name
            ))
        })?;

    let Some(sha256) = parse_sha256_asset(&text, &asset.name) else {
        return Ok(ChecksumResolution {
            asset_name: Some(checksum_asset.name.clone()),
            asset_url: Some(checksum_asset.browser_download_url.clone()),
            sha256: None,
            status: "A checksum asset exists, but ProjectX could not parse a SHA-256 value for the selected download."
                .to_string(),
        });
    };

    Ok(ChecksumResolution {
        asset_name: Some(checksum_asset.name.clone()),
        asset_url: Some(checksum_asset.browser_download_url.clone()),
        sha256: Some(sha256),
        status: format!("SHA-256 metadata is available in {}.", checksum_asset.name),
    })
}

fn parse_sha256_asset(text: &str, asset_name: &str) -> Option<String> {
    let lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    for line in lines {
        if let Some(hash) = extract_leading_sha256(line) {
            if line.contains(asset_name) || line.split_whitespace().count() == 1 {
                return Some(hash);
            }
        }
    }
    None
}

fn extract_leading_sha256(line: &str) -> Option<String> {
    let first = line.split_whitespace().next()?;
    normalize_sha256(first)
}

fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_start_matches('*');
    let candidate = trimmed
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    (candidate.len() == 64 && candidate.chars().all(|ch| ch.is_ascii_hexdigit()))
        .then(|| candidate.to_ascii_lowercase())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("Failed to open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn load_update_cache() -> Option<UpdateCache> {
    let path = crate::app_paths::update_cache_path();
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str::<UpdateCache>(&text).ok()
}

fn mutate_update_cache(mutator: impl FnOnce(&mut UpdateCache)) -> Result<(), String> {
    let config = github_release_config();
    let mut cache = load_update_cache().unwrap_or_else(|| UpdateCache {
        owner: config.owner.clone(),
        repo: config.repo.clone(),
        include_prereleases: config.include_prereleases,
        last_attempt_epoch: 0,
        last_successful_check_epoch: 0,
        last_status_kind: UpdateStatusKind::Unknown,
        last_error: None,
        latest_release: None,
        recent_attempts: Vec::new(),
        last_automatic_check_epoch: 0,
        last_downloaded_version: None,
        last_downloaded_asset_name: None,
        last_downloaded_asset_path: None,
        last_download_epoch: 0,
        last_download_status: None,
        last_install_status: None,
        last_install_attempt_epoch: 0,
        restart_required_after_install: false,
    });
    mutator(&mut cache);
    write_update_cache(&cache)
}

fn save_update_cache(
    config: &GitHubReleaseConfig,
    report: &UpdateCheckReport,
    now_epoch: u64,
) -> Result<(), String> {
    let mut cache = load_update_cache().unwrap_or_else(|| UpdateCache {
        owner: config.owner.clone(),
        repo: config.repo.clone(),
        include_prereleases: config.include_prereleases,
        last_attempt_epoch: 0,
        last_successful_check_epoch: 0,
        last_status_kind: UpdateStatusKind::Unknown,
        last_error: None,
        latest_release: None,
        recent_attempts: Vec::new(),
        last_automatic_check_epoch: 0,
        last_downloaded_version: None,
        last_downloaded_asset_name: None,
        last_downloaded_asset_path: None,
        last_download_epoch: 0,
        last_download_status: None,
        last_install_status: None,
        last_install_attempt_epoch: 0,
        restart_required_after_install: false,
    });

    cache.owner = config.owner.clone();
    cache.repo = config.repo.clone();
    cache.include_prereleases = config.include_prereleases;
    cache.last_attempt_epoch = now_epoch;
    cache.last_status_kind = report.status_kind;
    cache.last_error = report.last_error.clone();
    if report.latest_release.is_some() && report.status_kind != UpdateStatusKind::Error {
        cache.latest_release = report.latest_release.clone();
    }
    if report.last_successful_check_epoch > 0 {
        cache.last_successful_check_epoch = report.last_successful_check_epoch;
    }
    cache.recent_attempts.push(CachedAttempt {
        checked_epoch: now_epoch,
        status_kind: report.status_kind,
        error: report.last_error.clone(),
        latest_version: report
            .latest_release
            .as_ref()
            .map(|release| release.version.clone()),
    });
    if cache.recent_attempts.len() > MAX_CACHE_ATTEMPTS {
        let drain = cache.recent_attempts.len() - MAX_CACHE_ATTEMPTS;
        cache.recent_attempts.drain(0..drain);
    }

    write_update_cache(&cache)
}

fn write_update_cache(cache: &UpdateCache) -> Result<(), String> {
    let path = crate::app_paths::update_cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create update-cache directory: {error}"))?;
    }
    let text = serde_json::to_string_pretty(cache)
        .map_err(|error| format!("Failed to serialize update cache: {error}"))?;
    fs::write(path, text).map_err(|error| format!("Failed to write update cache: {error}"))
}

fn fetch_failure_message(failure: FetchFailure) -> String {
    match failure {
        FetchFailure::Offline(message)
        | FetchFailure::RateLimited(message)
        | FetchFailure::Error(message) => message,
    }
}

fn unique_download_path(dir: &Path, asset_name: &str) -> std::path::PathBuf {
    let sanitized = asset_name.trim();
    let candidate = dir.join(sanitized);
    if !candidate.exists() {
        return candidate;
    }
    let stem = Path::new(sanitized)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("projectx-update");
    let extension = Path::new(sanitized)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    for index in 1..1000 {
        let file_name = if extension.is_empty() {
            format!("{stem}-{index}")
        } else {
            format!("{stem}-{index}.{extension}")
        };
        let path = dir.join(file_name);
        if !path.exists() {
            return path;
        }
    }
    dir.join(format!("{}-{}", stem, now_fallback_suffix()))
}

fn now_fallback_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn env_value<'a>(env_map: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env_map
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn current_target_os() -> TargetOs {
    if cfg!(target_os = "macos") {
        TargetOs::MacOs
    } else if cfg!(target_os = "windows") {
        TargetOs::Windows
    } else {
        TargetOs::Linux
    }
}

fn current_target_arch() -> TargetArch {
    match std::env::consts::ARCH {
        "x86_64" => TargetArch::X86_64,
        "aarch64" => TargetArch::Aarch64,
        _ => TargetArch::Other,
    }
}

fn os_aliases(target: TargetOs) -> (&'static [&'static str], &'static [&'static str]) {
    match target {
        TargetOs::MacOs => (&["macos", "darwin", "osx", "mac"], &["windows", "linux"]),
        TargetOs::Windows => (
            &["windows", "win64", "win32", "win"],
            &["macos", "darwin", "linux"],
        ),
        TargetOs::Linux => (
            &["linux", "appimage", "gnu"],
            &["windows", "macos", "darwin"],
        ),
    }
}

fn arch_aliases(target: TargetArch) -> (&'static [&'static str], &'static [&'static str]) {
    match target {
        TargetArch::X86_64 => (&["x86_64", "amd64", "x64", "win64"], &["arm64", "aarch64"]),
        TargetArch::Aarch64 => (&["arm64", "aarch64"], &["x86_64", "amd64", "x64"]),
        TargetArch::Other => (&[], &[]),
    }
}

fn os_hint_score(name: &str, target: TargetOs) -> OsHint {
    let (positive, negative) = os_aliases(target);
    if let Some(label) = negative.iter().find(|label| name.contains(**label)) {
        return OsHint::Conflict((*label).to_string());
    }
    if let Some(label) = positive.iter().find(|label| name.contains(**label)) {
        return OsHint::Match((*label).to_string());
    }
    OsHint::Unknown
}

fn arch_hint_score(name: &str, target: TargetArch) -> ArchHint {
    let (positive, negative) = arch_aliases(target);
    if let Some(label) = negative.iter().find(|label| name.contains(**label)) {
        return ArchHint::Conflict((*label).to_string());
    }
    if let Some(label) = positive.iter().find(|label| name.contains(**label)) {
        return ArchHint::Match((*label).to_string());
    }
    ArchHint::Unknown
}

fn checksum_matches_asset_name(checksum_name: &str, asset_name: &str) -> bool {
    let checksum_lower = checksum_name.to_ascii_lowercase();
    let asset_lower = asset_name.to_ascii_lowercase();
    checksum_lower.contains(&asset_lower)
        || checksum_lower == format!("{asset_lower}.sha256")
        || checksum_lower == format!("{asset_lower}.sha256.txt")
}

fn is_checksum_asset_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sha256") || lower.ends_with(".sha256.txt")
}

fn parse_version_option(value: &str) -> Option<ParsedVersion> {
    let parsed = parse_version(value);
    (!parsed.numeric_parts.is_empty()).then_some(parsed)
}

fn parse_version(value: &str) -> ParsedVersion {
    let normalized = normalize_version_label(value);
    let mut version_and_build = normalized.splitn(2, '+');
    let without_build = version_and_build.next().unwrap_or_default();
    let mut version_and_pre = without_build.splitn(2, '-');
    let core = version_and_pre.next().unwrap_or_default();
    let prerelease = version_and_pre.next().unwrap_or_default();
    let numeric_parts = core
        .split('.')
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok())
        .collect::<Vec<_>>();
    let prerelease = prerelease
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| {
            if part.chars().all(|ch| ch.is_ascii_digit()) {
                PreIdentifier::Numeric(part.parse::<u64>().unwrap_or(0))
            } else {
                PreIdentifier::Text(part.to_ascii_lowercase())
            }
        })
        .collect::<Vec<_>>();

    ParsedVersion {
        normalized: without_build.to_string(),
        numeric_parts,
        prerelease,
    }
}

fn compare_parsed_versions(left: &ParsedVersion, right: &ParsedVersion) -> Ordering {
    for index in 0..left.numeric_parts.len().max(right.numeric_parts.len()) {
        let left_part = *left.numeric_parts.get(index).unwrap_or(&0);
        let right_part = *right.numeric_parts.get(index).unwrap_or(&0);
        match left_part.cmp(&right_part) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    match (left.prerelease.is_empty(), right.prerelease.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => compare_prerelease(&left.prerelease, &right.prerelease),
    }
}

fn compare_prerelease(left: &[PreIdentifier], right: &[PreIdentifier]) -> Ordering {
    for index in 0..left.len().max(right.len()) {
        match (left.get(index), right.get(index)) {
            (Some(PreIdentifier::Numeric(lhs)), Some(PreIdentifier::Numeric(rhs))) => {
                match lhs.cmp(rhs) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
            (Some(PreIdentifier::Text(lhs)), Some(PreIdentifier::Text(rhs))) => {
                match lhs.cmp(rhs) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
            (Some(PreIdentifier::Numeric(_)), Some(PreIdentifier::Text(_))) => {
                return Ordering::Less
            }
            (Some(PreIdentifier::Text(_)), Some(PreIdentifier::Numeric(_))) => {
                return Ordering::Greater
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
    Ordering::Equal
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GitHubRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GitHubAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    browser_download_url: String,
    #[serde(default)]
    content_type: String,
}

#[derive(Debug, Clone)]
struct ScoredAsset {
    asset: GitHubAsset,
    score: i32,
    reason: String,
}

#[derive(Debug, Clone)]
struct ChecksumResolution {
    asset_name: Option<String>,
    asset_url: Option<String>,
    sha256: Option<String>,
    status: String,
}

#[derive(Debug, Clone, Copy)]
enum AssetExtension {
    Dmg,
    Zip,
    Exe,
    Msi,
    AppImage,
    TarGz,
    TarXz,
    Deb,
    Rpm,
}

impl AssetExtension {
    fn label(self) -> &'static str {
        match self {
            Self::Dmg => "dmg",
            Self::Zip => "zip",
            Self::Exe => "exe",
            Self::Msi => "msi",
            Self::AppImage => "AppImage",
            Self::TarGz => "tar.gz",
            Self::TarXz => "tar.xz",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
        }
    }

    fn content_type_hint(self) -> &'static str {
        match self {
            Self::Dmg => "diskimage",
            Self::Zip => "zip",
            Self::Exe | Self::Msi => "octet-stream",
            Self::AppImage => "octet-stream",
            Self::TarGz | Self::TarXz => "gzip",
            Self::Deb => "debian",
            Self::Rpm => "rpm",
        }
    }
}

#[derive(Debug, Clone)]
enum OsHint {
    Match(String),
    Conflict(String),
    Unknown,
}

#[derive(Debug, Clone)]
enum ArchHint {
    Match(String),
    Conflict(String),
    Unknown,
}

impl TargetOs {
    fn label(self) -> &'static str {
        match self {
            Self::MacOs => "macOS",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
        }
    }
}

impl TargetArch {
    fn label(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "arm64",
            Self::Other => "current architecture",
        }
    }
}

fn detect_asset_extension(name: &str) -> Option<AssetExtension> {
    if name.ends_with(".tar.gz") {
        Some(AssetExtension::TarGz)
    } else if name.ends_with(".tar.xz") {
        Some(AssetExtension::TarXz)
    } else if name.ends_with(".appimage") {
        Some(AssetExtension::AppImage)
    } else if name.ends_with(".dmg") {
        Some(AssetExtension::Dmg)
    } else if name.ends_with(".zip") {
        Some(AssetExtension::Zip)
    } else if name.ends_with(".exe") {
        Some(AssetExtension::Exe)
    } else if name.ends_with(".msi") {
        Some(AssetExtension::Msi)
    } else if name.ends_with(".deb") {
        Some(AssetExtension::Deb)
    } else if name.ends_with(".rpm") {
        Some(AssetExtension::Rpm)
    } else {
        None
    }
}

fn package_score(target_os: TargetOs, ext: AssetExtension) -> Option<i32> {
    match target_os {
        TargetOs::MacOs => match ext {
            AssetExtension::Dmg => Some(120),
            AssetExtension::Zip => Some(90),
            AssetExtension::TarGz | AssetExtension::TarXz => Some(55),
            _ => None,
        },
        TargetOs::Windows => match ext {
            AssetExtension::Exe => Some(120),
            AssetExtension::Msi => Some(110),
            AssetExtension::Zip => Some(95),
            _ => None,
        },
        TargetOs::Linux => match ext {
            AssetExtension::AppImage => Some(120),
            AssetExtension::TarGz => Some(100),
            AssetExtension::TarXz => Some(95),
            AssetExtension::Deb => Some(90),
            AssetExtension::Rpm => Some(90),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_map(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn release(tag: &str, prerelease: bool, asset_names: &[&str]) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.to_string(),
            prerelease,
            html_url: format!("https://example.invalid/{tag}"),
            published_at: Some(format!("{tag}T00:00:00Z")),
            assets: asset_names
                .iter()
                .map(|name| GitHubAsset {
                    name: (*name).to_string(),
                    browser_download_url: format!("https://example.invalid/{name}"),
                    content_type: if name.ends_with(".dmg") {
                        "application/x-apple-diskimage".to_string()
                    } else if name.ends_with(".zip") {
                        "application/zip".to_string()
                    } else {
                        "application/octet-stream".to_string()
                    },
                })
                .collect(),
            ..GitHubRelease::default()
        }
    }

    #[test]
    fn stable_release_is_selected_over_prerelease_by_default() {
        let releases = vec![
            release("v1.3.0-beta.1", true, &["ProjectX-macos.dmg"]),
            release("v1.2.0", false, &["ProjectX-macos.dmg"]),
        ];
        let result = select_release(
            &Client::new(),
            &GitHubReleaseConfig {
                owner: DEFAULT_OWNER.to_string(),
                repo: DEFAULT_REPO.to_string(),
                token: None,
                include_prereleases: false,
            },
            &releases,
        );
        let release = result.expect("stable release");
        assert_eq!(release.version, "1.2.0");
    }

    #[test]
    fn prereleases_can_be_included_explicitly() {
        let releases = vec![release("v1.3.0-beta.1", true, &["ProjectX-macos.dmg"])];
        let result = select_release(
            &Client::new(),
            &GitHubReleaseConfig {
                owner: DEFAULT_OWNER.to_string(),
                repo: DEFAULT_REPO.to_string(),
                token: None,
                include_prereleases: true,
            },
            &releases,
        );
        let release = result.expect("prerelease");
        assert_eq!(release.version, "1.3.0-beta.1");
    }

    #[test]
    fn release_selection_sorts_by_version_not_input_order() {
        let releases = vec![
            release("v1.2.0", false, &["ProjectX-macos.dmg"]),
            release("v1.10.0", false, &["ProjectX-macos.dmg"]),
        ];
        let result = select_release(
            &Client::new(),
            &GitHubReleaseConfig {
                owner: DEFAULT_OWNER.to_string(),
                repo: DEFAULT_REPO.to_string(),
                token: None,
                include_prereleases: false,
            },
            &releases,
        );
        let release = result.expect("sorted release");
        assert_eq!(release.version, "1.10.0");
    }

    #[test]
    fn version_comparison_handles_v_prefixes() {
        assert_eq!(compare_versions("v1.2.3", "1.2.3"), Ordering::Equal);
        assert!(is_version_newer("v1.2.4", "1.2.3"));
    }

    #[test]
    fn semver_prerelease_comparison_is_more_precise() {
        assert!(is_version_newer("1.2.3-beta.11", "1.2.3-beta.2"));
        assert!(is_version_newer("1.2.3", "1.2.3-rc.1"));
        assert!(!is_version_newer("1.2.3-alpha", "1.2.3"));
    }

    #[test]
    fn public_repo_config_does_not_require_token() {
        let config = github_release_config_from_env_map(&env_map(&[]));
        let request = apply_request_headers(Client::new().get("https://example.invalid"), &config)
            .build()
            .expect("request");
        assert!(request.headers().get(AUTHORIZATION).is_none());
    }

    #[test]
    fn token_is_attached_when_configured() {
        let config =
            github_release_config_from_env_map(&env_map(&[("PROJECTX_GITHUB_TOKEN", "abc123")]));
        let request = apply_request_headers(Client::new().get("https://example.invalid"), &config)
            .build()
            .expect("request");
        assert_eq!(
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer abc123")
        );
    }

    #[test]
    fn rate_limit_is_classified_explicitly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining",
            reqwest::header::HeaderValue::from_static("0"),
        );
        let failure = classify_http_failure(reqwest::StatusCode::FORBIDDEN, &headers, "rate limit");
        assert!(matches!(failure, FetchFailure::RateLimited(_)));
    }

    #[test]
    fn offline_failure_uses_cached_release_without_claiming_success() {
        let config = github_release_config_from_env_map(&env_map(&[]));
        let report = build_failure_report(
            &config,
            "0.1.0".to_string(),
            200,
            FetchFailure::Offline("offline".to_string()),
            Some(UpdateCache {
                owner: config.owner.clone(),
                repo: config.repo.clone(),
                include_prereleases: false,
                last_attempt_epoch: 150,
                last_successful_check_epoch: 100,
                last_status_kind: UpdateStatusKind::UpToDate,
                last_error: None,
                latest_release: Some(ReleaseInfo {
                    version: "0.2.0".to_string(),
                    tag_name: "v0.2.0".to_string(),
                    published_at: "2026-04-01T00:00:00Z".to_string(),
                    html_url: "https://example.invalid/releases/v0.2.0".to_string(),
                    body: String::new(),
                    asset_name: "ProjectX-macos.dmg".to_string(),
                    asset_url: "https://example.invalid/ProjectX-macos.dmg".to_string(),
                    asset_content_type: "application/x-apple-diskimage".to_string(),
                    asset_match_reason: "package dmg, os macos".to_string(),
                    checksum_asset_name: Some("ProjectX-macos.dmg.sha256".to_string()),
                    checksum_asset_url: Some(
                        "https://example.invalid/ProjectX-macos.dmg.sha256".to_string(),
                    ),
                    expected_sha256: Some("a".repeat(64)),
                    checksum_status: "SHA-256 metadata is available.".to_string(),
                }),
                recent_attempts: Vec::new(),
                last_automatic_check_epoch: 0,
                last_downloaded_version: None,
                last_downloaded_asset_name: None,
                last_downloaded_asset_path: None,
                last_download_epoch: 0,
                last_download_status: None,
                last_install_status: None,
                last_install_attempt_epoch: 0,
                restart_required_after_install: false,
            }),
        );
        assert_eq!(report.status_kind, UpdateStatusKind::Offline);
        assert!(report.used_cached_release);
        assert!(report.available_update.is_some());
    }

    #[test]
    fn asset_matching_prefers_native_package_type() {
        let assets = vec![
            GitHubAsset {
                name: "ProjectX-macos.zip".to_string(),
                browser_download_url: String::new(),
                content_type: "application/zip".to_string(),
            },
            GitHubAsset {
                name: "ProjectX-macos.dmg".to_string(),
                browser_download_url: String::new(),
                content_type: "application/x-apple-diskimage".to_string(),
            },
        ];
        match select_platform_asset(&assets) {
            AssetSelectionOutcome::Selected(selection) => {
                assert_eq!(selection.asset.name, "ProjectX-macos.dmg");
            }
            other => panic!("unexpected asset selection result: {other:?}"),
        }
    }

    #[test]
    fn ambiguous_asset_selection_is_reported() {
        let assets = vec![
            GitHubAsset {
                name: "ProjectX-macos-universal.zip".to_string(),
                browser_download_url: String::new(),
                content_type: "application/zip".to_string(),
            },
            GitHubAsset {
                name: "ProjectX-darwin.zip".to_string(),
                browser_download_url: String::new(),
                content_type: "application/zip".to_string(),
            },
        ];
        assert!(matches!(
            select_platform_asset(&assets),
            AssetSelectionOutcome::Ambiguous(_)
        ));
    }

    #[test]
    fn checksum_assets_can_be_parsed() {
        let parsed = parse_sha256_asset(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ProjectX-macos.dmg",
            "ProjectX-macos.dmg",
        );
        assert_eq!(
            parsed,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
    }

    #[test]
    fn verify_downloaded_asset_works() {
        let path = std::env::temp_dir().join("projectx-update-test.bin");
        fs::write(&path, b"projectx").expect("write temp file");
        let hash = sha256_file(&path).expect("hash");
        let result = verify_downloaded_asset(&path, &hash);
        fs::remove_file(&path).ok();
        assert!(result.is_ok());
    }

    #[test]
    fn status_kind_user_labels_are_product_facing() {
        assert_eq!(
            UpdateStatusKind::UpdateAvailable.user_label(),
            "Update available"
        );
        assert!(UpdateStatusKind::Offline
            .user_summary()
            .contains("could not be reached"));
    }
}

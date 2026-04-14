use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};

const DEFAULT_OWNER: &str = "ColtG-28";
const DEFAULT_REPO: &str = "ProjectX";
const API_BASE: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";
const UPDATE_TIMEOUT: Duration = Duration::from_secs(12);

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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: String,
    pub tag_name: String,
    pub published_at: String,
    pub html_url: String,
    pub asset_name: String,
    pub asset_url: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCache {
    pub checked_epoch: u64,
    pub owner: String,
    pub repo: String,
    pub include_prereleases: bool,
    pub release: ReleaseInfo,
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

pub fn check_for_updates(now_epoch: u64) -> UpdateCheckReport {
    let config = github_release_config();
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let release_page_url = releases_page_url(&config.owner, &config.repo);
    let repo_label = format!("{}/{}", config.owner, config.repo);
    let client = build_client();
    let cached = load_cached_release();

    match client.and_then(|client| fetch_release(&client, &config)) {
        Ok(release) => {
            let _ = save_cached_release(&config, &release, now_epoch);
            build_report(
                &config,
                current_version,
                release,
                now_epoch,
                now_epoch,
                None,
                false,
            )
        }
        Err(failure) => build_report_from_failure(
            &config,
            current_version,
            now_epoch,
            failure,
            cached,
            release_page_url,
            repo_label,
        ),
    }
}

pub fn github_release_config() -> GitHubReleaseConfig {
    github_release_config_from_env_map(&std::env::vars().collect::<HashMap<_, _>>())
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

fn build_report_from_failure(
    config: &GitHubReleaseConfig,
    current_version: String,
    now_epoch: u64,
    failure: FetchFailure,
    cached: Option<UpdateCache>,
    release_page_url: String,
    repo_label: String,
) -> UpdateCheckReport {
    let (status_kind, last_error) = match failure {
        FetchFailure::Offline(message) => (UpdateStatusKind::Offline, Some(message)),
        FetchFailure::RateLimited(message) => (UpdateStatusKind::RateLimited, Some(message)),
        FetchFailure::Error(message) => (UpdateStatusKind::Error, Some(message)),
    };

    if let Some(cache) =
        cached.filter(|cache| cache.owner == config.owner && cache.repo == config.repo)
    {
        let cached_release = cache.release;
        let has_update = is_version_newer(&cached_release.version, &current_version);
        let latest_release = Some(cached_release.clone());
        return UpdateCheckReport {
            current_version,
            available_update: has_update.then_some(cached_release.clone()),
            latest_release,
            last_checked_epoch: now_epoch,
            last_successful_check_epoch: cache.checked_epoch,
            status_label: format!(
                "{}. Showing cached release metadata from {}.",
                status_error_prefix(status_kind),
                cache.checked_epoch
            ),
            last_error,
            status_kind,
            repo_label,
            release_page_url,
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
        status_label: status_error_prefix(status_kind).to_string(),
        last_error,
        repo_label,
        release_page_url,
        used_cached_release: false,
    }
}

fn status_error_prefix(kind: UpdateStatusKind) -> &'static str {
    match kind {
        UpdateStatusKind::Offline => "GitHub could not be reached",
        UpdateStatusKind::RateLimited => "GitHub API rate limit was reached",
        UpdateStatusKind::Error => "The GitHub release check failed",
        _ => "Update status is unknown",
    }
}

fn build_report(
    config: &GitHubReleaseConfig,
    current_version: String,
    release: ReleaseInfo,
    now_epoch: u64,
    success_epoch: u64,
    last_error: Option<String>,
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
        last_successful_check_epoch: success_epoch,
        status_kind,
        status_label,
        last_error,
        repo_label: format!("{}/{}", config.owner, config.repo),
        release_page_url: releases_page_url(&config.owner, &config.repo),
        used_cached_release,
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
        "{API_BASE}/repos/{}/{}/releases?per_page=20",
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

    release_from_list(&releases, config.include_prereleases)
        .ok_or_else(|| FetchFailure::Error("No matching published release was found.".to_string()))
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

fn release_from_list(releases: &[GitHubRelease], include_prereleases: bool) -> Option<ReleaseInfo> {
    releases
        .iter()
        .filter(|release| !release.draft)
        .filter(|release| include_prereleases || !release.prerelease)
        .find_map(convert_release)
}

fn convert_release(release: &GitHubRelease) -> Option<ReleaseInfo> {
    let tag_name = release.tag_name.trim().to_string();
    if tag_name.is_empty() {
        return None;
    }
    let version = normalize_version_label(&tag_name);
    if version.is_empty() {
        return None;
    }
    let asset = select_platform_asset(&release.assets)?;

    Some(ReleaseInfo {
        version,
        tag_name,
        published_at: release
            .published_at
            .clone()
            .or_else(|| release.created_at.clone())
            .unwrap_or_default(),
        html_url: release.html_url.clone(),
        asset_name: asset.name.clone(),
        asset_url: asset.browser_download_url.clone(),
        body: release.body.clone().unwrap_or_default(),
    })
}

fn select_platform_asset(assets: &[GitHubAsset]) -> Option<&GitHubAsset> {
    let expected_platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    let mut matching = assets
        .iter()
        .filter(|asset| {
            let name = asset.name.to_ascii_lowercase();
            name.contains(expected_platform) && !name.ends_with(".sha256")
        })
        .collect::<Vec<_>>();

    matching.sort_by_key(|asset| platform_asset_rank(&asset.name));
    matching.into_iter().next()
}

fn platform_asset_rank(name: &str) -> usize {
    let lower = name.to_ascii_lowercase();
    if cfg!(target_os = "macos") {
        if lower.ends_with(".dmg") {
            return 0;
        }
        if lower.ends_with(".zip") {
            return 1;
        }
    } else if cfg!(target_os = "windows") {
        if lower.ends_with(".exe") {
            return 0;
        }
        if lower.ends_with(".zip") {
            return 1;
        }
    } else {
        if lower.ends_with(".appimage") {
            return 0;
        }
        if lower.ends_with(".tar.gz") {
            return 1;
        }
    }
    10
}

pub fn normalize_version_label(version: &str) -> String {
    version
        .trim()
        .trim_start_matches('v')
        .trim_start_matches('V')
        .to_string()
}

pub fn is_version_newer(candidate: &str, current: &str) -> bool {
    compare_versions(candidate, current).is_gt()
}

pub fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left = parse_version(left);
    let right = parse_version(right);

    for index in 0..left.parts.len().max(right.parts.len()) {
        let left_part = *left.parts.get(index).unwrap_or(&0);
        let right_part = *right.parts.get(index).unwrap_or(&0);
        match left_part.cmp(&right_part) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    match (left.prerelease.is_empty(), right.prerelease.is_empty()) {
        (true, true) | (false, false) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
    }
}

pub fn releases_page_url(owner: &str, repo: &str) -> String {
    format!("https://github.com/{owner}/{repo}/releases")
}

fn load_cached_release() -> Option<UpdateCache> {
    let path = crate::app_paths::update_cache_path();
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str::<UpdateCache>(&text).ok()
}

fn save_cached_release(
    config: &GitHubReleaseConfig,
    release: &ReleaseInfo,
    now_epoch: u64,
) -> Result<(), String> {
    let cache = UpdateCache {
        checked_epoch: now_epoch,
        owner: config.owner.clone(),
        repo: config.repo.clone(),
        include_prereleases: config.include_prereleases,
        release: release.clone(),
    };
    let path = crate::app_paths::update_cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create update-cache directory: {error}"))?;
    }
    let text = serde_json::to_string_pretty(&cache)
        .map_err(|error| format!("Failed to serialize update cache: {error}"))?;
    fs::write(path, text).map_err(|error| format!("Failed to write update cache: {error}"))
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
}

#[derive(Debug, Clone, Default)]
struct ParsedVersion {
    parts: Vec<u64>,
    prerelease: String,
}

fn parse_version(value: &str) -> ParsedVersion {
    let normalized = normalize_version_label(value);
    let mut split = normalized.splitn(2, '-');
    let base = split.next().unwrap_or_default();
    let prerelease = split.next().unwrap_or_default().to_string();
    let parts = base
        .split('.')
        .filter_map(|part| {
            let digits = part
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            (!digits.is_empty())
                .then(|| digits.parse::<u64>().ok())
                .flatten()
        })
        .collect::<Vec<_>>();
    ParsedVersion { parts, prerelease }
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

    #[test]
    fn stable_release_is_selected_over_prerelease_by_default() {
        let releases = vec![
            GitHubRelease {
                tag_name: "v1.3.0-beta.1".to_string(),
                prerelease: true,
                html_url: "https://example.invalid/pre".to_string(),
                assets: vec![GitHubAsset {
                    name: "ProjectX-macos.dmg".to_string(),
                    browser_download_url: "https://example.invalid/pre.dmg".to_string(),
                }],
                ..GitHubRelease::default()
            },
            GitHubRelease {
                tag_name: "v1.2.0".to_string(),
                html_url: "https://example.invalid/stable".to_string(),
                assets: vec![GitHubAsset {
                    name: "ProjectX-macos.dmg".to_string(),
                    browser_download_url: "https://example.invalid/stable.dmg".to_string(),
                }],
                ..GitHubRelease::default()
            },
        ];

        let release = release_from_list(&releases, false).expect("stable release");
        assert_eq!(release.version, "1.2.0");
    }

    #[test]
    fn prereleases_can_be_included_explicitly() {
        let releases = vec![GitHubRelease {
            tag_name: "v1.3.0-beta.1".to_string(),
            prerelease: true,
            html_url: "https://example.invalid/pre".to_string(),
            assets: vec![GitHubAsset {
                name: "ProjectX-macos.dmg".to_string(),
                browser_download_url: "https://example.invalid/pre.dmg".to_string(),
            }],
            ..GitHubRelease::default()
        }];

        let release = release_from_list(&releases, true).expect("prerelease");
        assert_eq!(release.version, "1.3.0-beta.1");
    }

    #[test]
    fn version_comparison_handles_v_prefixes() {
        assert_eq!(
            compare_versions("v1.2.3", "1.2.3"),
            std::cmp::Ordering::Equal
        );
        assert!(is_version_newer("v1.2.4", "1.2.3"));
    }

    #[test]
    fn stable_release_beats_matching_prerelease() {
        assert!(is_version_newer("1.2.3", "1.2.3-beta.1"));
        assert!(!is_version_newer("1.2.3-beta.1", "1.2.3"));
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
        let report = build_report_from_failure(
            &config,
            "0.1.0".to_string(),
            200,
            FetchFailure::Offline("offline".to_string()),
            Some(UpdateCache {
                checked_epoch: 100,
                owner: config.owner.clone(),
                repo: config.repo.clone(),
                include_prereleases: false,
                release: ReleaseInfo {
                    version: "0.2.0".to_string(),
                    tag_name: "v0.2.0".to_string(),
                    published_at: "2026-04-01T00:00:00Z".to_string(),
                    html_url: "https://example.invalid/releases/v0.2.0".to_string(),
                    asset_name: "ProjectX-macos.dmg".to_string(),
                    asset_url: "https://example.invalid/ProjectX-macos.dmg".to_string(),
                    body: String::new(),
                },
            }),
            releases_page_url(&config.owner, &config.repo),
            format!("{}/{}", config.owner, config.repo),
        );
        assert_eq!(report.status_kind, UpdateStatusKind::Offline);
        assert!(report.used_cached_release);
        assert!(report.available_update.is_some());
    }
}

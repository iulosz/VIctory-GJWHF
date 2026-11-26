//! Periodic process/system memory telemetry for diagnostic runs.
//!
//! Samples are deliberately taken on a background thread. The title's
//! presentation path never waits for telemetry, and a failed sample does
//! not stop the title. The CSV separates resident RAM (working set) from
//! private commit (PagefileUsage), which are different measurements.

use std::collections::{HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::System::ProcessStatus::{
    K32GetPerformanceInfo, K32GetProcessMemoryInfo, PERFORMANCE_INFORMATION,
    PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const HEADER: &str = concat!(
    "unix_ms,pid,working_set_bytes,private_working_set_bytes,peak_working_set_bytes,",
    "private_commit_bytes,peak_private_commit_bytes,shared_commit_bytes,paged_pool_bytes,",
    "nonpaged_pool_bytes,page_faults_total,",
    "page_faults_delta,rust_heap_bytes,placed_texture_bytes_created_total,",
    "list_upload_blocks,list_upload_bytes,system_total_ram_bytes,system_available_ram_bytes,",
    "system_memory_load_percent,system_commit_total_bytes,system_commit_limit_bytes,",
    "system_commit_peak_bytes,system_commit_available_bytes,video_local_usage_bytes,",
    "video_local_budget_bytes,video_nonlocal_usage_bytes,video_nonlocal_budget_bytes,",
    "working_set_delta_bytes,working_set_growth_window_bytes,",
    "alert_codes"
);

static ACTIVE_LOG: OnceLock<PathBuf> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
struct Sample {
    unix_ms: u128,
    pid: u32,
    working_set: u64,
    private_working_set: Option<u64>,
    peak_working_set: u64,
    private_commit: u64,
    peak_private_commit: u64,
    shared_commit: Option<u64>,
    paged_pool: u64,
    nonpaged_pool: u64,
    page_faults: u64,
    rust_heap: u64,
    placed_texture_bytes: u64,
    upload_blocks: u64,
    upload_bytes: u64,
    total_ram: u64,
    available_ram: u64,
    memory_load_percent: u32,
    system_commit_total: u64,
    system_commit_limit: u64,
    system_commit_peak: u64,
    system_commit_available: u64,
    video_local_usage: Option<u64>,
    video_local_budget: Option<u64>,
    video_nonlocal_usage: Option<u64>,
    video_nonlocal_budget: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Alert {
    code: &'static str,
    critical: bool,
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn target_bytes() -> u64 {
    std::env::var("VICTORY_MEMORY_TARGET_GIB")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=128).contains(value))
        .unwrap_or(10)
        .saturating_mul(GIB)
}

fn sample_interval() -> Duration {
    let millis = std::env::var("VICTORY_MEMORY_SAMPLE_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000)
        .clamp(250, 10_000);
    Duration::from_millis(millis)
}

/// Starts one monitor per process and returns the CSV path.
///
/// The caller must supply a directory that has already passed the
/// repository's asset-path policy.
pub fn start(directory: &Path) -> std::io::Result<PathBuf> {
    if let Some(path) = ACTIVE_LOG.get() {
        return Ok(path.clone());
    }

    std::fs::create_dir_all(directory)?;
    let pid = std::process::id();
    let path = directory.join(format!("memory-{pid}-{}.csv", now_unix_ms()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "# VIctory memory telemetry; target_working_set_bytes={}", target_bytes())?;
    writeln!(writer, "{HEADER}")?;
    writer.flush()?;

    let interval = sample_interval();
    let target = target_bytes();
    std::thread::Builder::new()
        .name("victory-memory-monitor".into())
        .spawn(move || sample_loop(writer, interval, target))?;

    let _ = ACTIVE_LOG.set(path.clone());
    tracing::info!(
        path = %path.display(),
        sample_ms = interval.as_millis(),
        target_gib = target / GIB,
        "memory telemetry started"
    );
    Ok(path)
}

fn collect() -> std::io::Result<Sample> {
    let mut extended: PROCESS_MEMORY_COUNTERS_EX2 = unsafe { std::mem::zeroed() };
    extended.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
    // SAFETY: GetCurrentProcess returns a pseudo-handle for this process;
    // the extended structure is writable and cb advertises its exact size.
    let extended_ok = unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&mut extended as *mut PROCESS_MEMORY_COUNTERS_EX2).cast(),
            extended.cb,
        )
    };

    // PROCESS_MEMORY_COUNTERS_EX2 adds private resident working set and shared
    // commit. Windows versions without EX2 support fall back to the base
    // counters, leaving those two fields unavailable rather than failing.
    let (
        working_set,
        private_working_set,
        peak_working_set,
        private_commit,
        peak_private_commit,
        shared_commit,
        paged_pool,
        nonpaged_pool,
        page_faults,
    ) = if extended_ok != 0 {
        (
            extended.WorkingSetSize as u64,
            Some(extended.PrivateWorkingSetSize as u64),
            extended.PeakWorkingSetSize as u64,
            extended.PrivateUsage as u64,
            extended.PeakPagefileUsage as u64,
            Some(extended.SharedCommitUsage),
            extended.QuotaPagedPoolUsage as u64,
            extended.QuotaNonPagedPoolUsage as u64,
            u64::from(extended.PageFaultCount),
        )
    } else {
        let mut base = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        // SAFETY: as above, with the older, smaller counter structure.
        let base_ok = unsafe {
            K32GetProcessMemoryInfo(GetCurrentProcess(), &mut base, base.cb)
        };
        if base_ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        (
            base.WorkingSetSize as u64,
            None,
            base.PeakWorkingSetSize as u64,
            base.PagefileUsage as u64,
            base.PeakPagefileUsage as u64,
            None,
            base.QuotaPagedPoolUsage as u64,
            base.QuotaNonPagedPoolUsage as u64,
            u64::from(base.PageFaultCount),
        )
    };

    // SAFETY: MEMORYSTATUSEX is plain output data. dwLength is required by
    // GlobalMemoryStatusEx and all other fields are initialized to zero.
    let mut system: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    system.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut system) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // GlobalMemoryStatusEx is useful for physical RAM availability. Get
    // system-wide commit totals separately: the page counts are multiplied
    // by the reported page size, as required by PERFORMANCE_INFORMATION.
    let mut performance: PERFORMANCE_INFORMATION = unsafe { std::mem::zeroed() };
    performance.cb = std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
    if unsafe { K32GetPerformanceInfo(&mut performance, performance.cb) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let page_size = performance.PageSize as u64;
    let commit_total = (performance.CommitTotal as u64).saturating_mul(page_size);
    let commit_limit = (performance.CommitLimit as u64).saturating_mul(page_size);
    let commit_peak = (performance.CommitPeak as u64).saturating_mul(page_size);

    let video = crate::host::video_memory().map(|segments| {
        // host::video_memory reports decimal MB for its existing log line.
        // Convert back to bytes for the CSV; values are diagnostic estimates.
        let bytes = |mb: f64| (mb.max(0.0) * 1_000_000.0) as u64;
        [
            (bytes(segments[0].0), bytes(segments[0].1)),
            (bytes(segments[1].0), bytes(segments[1].1)),
        ]
    });

    Ok(Sample {
        unix_ms: now_unix_ms(),
        pid: std::process::id(),
        working_set,
        private_working_set,
        peak_working_set,
        private_commit,
        peak_private_commit,
        shared_commit,
        paged_pool,
        nonpaged_pool,
        page_faults,
        rust_heap: crate::copystat::HEAP_BYTES.load(std::sync::atomic::Ordering::Relaxed),
        // PLACED_BYTES counts texture allocations made during this process;
        // it is cumulative, unlike the current DXGI usage and upload counters.
        placed_texture_bytes: crate::resource::PLACED_BYTES
            .load(std::sync::atomic::Ordering::Relaxed),
        upload_blocks: crate::list::UPLOADS[0].load(std::sync::atomic::Ordering::Relaxed),
        upload_bytes: crate::list::UPLOADS[1].load(std::sync::atomic::Ordering::Relaxed),
        total_ram: system.ullTotalPhys,
        available_ram: system.ullAvailPhys,
        memory_load_percent: system.dwMemoryLoad,
        system_commit_total: commit_total,
        system_commit_limit: commit_limit,
        system_commit_peak: commit_peak,
        system_commit_available: commit_limit.saturating_sub(commit_total),
        video_local_usage: video.map(|v| v[0].0),
        video_local_budget: video.map(|v| v[0].1),
        video_nonlocal_usage: video.map(|v| v[1].0),
        video_nonlocal_budget: video.map(|v| v[1].1),
    })
}

fn signed_delta(current: u64, previous: u64) -> i128 {
    i128::from(current) - i128::from(previous)
}

fn growth_over_window(
    history: &VecDeque<(Instant, u64)>,
    now: Instant,
    current_working_set: u64,
) -> Option<i128> {
    let (at, bytes) = history
        .iter()
        .find(|(at, _)| now.duration_since(*at) >= Duration::from_secs(8))?;
    Some(signed_delta(current_working_set, *bytes))
}

fn evaluate(sample: &Sample, target: u64, growth: Option<i128>) -> Vec<Alert> {
    let mut alerts = Vec::new();

    if sample.working_set >= target {
        alerts.push(Alert { code: "RAM_TARGET_EXCEEDED", critical: true });
    } else if sample.working_set >= target.saturating_mul(9) / 10 {
        alerts.push(Alert { code: "RAM_TARGET_NEAR", critical: false });
    } else if sample.working_set >= target.saturating_mul(8) / 10 {
        alerts.push(Alert { code: "RAM_TARGET_APPROACHING", critical: false });
    }

    if sample.available_ram <= GIB {
        alerts.push(Alert { code: "SYSTEM_RAM_CRITICAL", critical: true });
    } else if sample.available_ram <= 2 * GIB {
        alerts.push(Alert { code: "SYSTEM_RAM_LOW", critical: false });
    }

    if sample.memory_load_percent >= 95 {
        alerts.push(Alert { code: "SYSTEM_MEMORY_LOAD_CRITICAL", critical: true });
    } else if sample.memory_load_percent >= 90 {
        alerts.push(Alert { code: "SYSTEM_MEMORY_LOAD_HIGH", critical: false });
    }

    if sample.system_commit_available <= GIB {
        alerts.push(Alert { code: "SYSTEM_COMMIT_CRITICAL", critical: true });
    } else if sample.system_commit_available <= 2 * GIB {
        alerts.push(Alert { code: "SYSTEM_COMMIT_LOW", critical: false });
    }

    if growth.is_some_and(|bytes| bytes >= i128::from(512 * MIB)) {
        alerts.push(Alert { code: "RAM_GROWTH_SPIKE", critical: false });
    }

    alerts
}

fn log_transitions(
    previous: &mut HashSet<&'static str>,
    current: &[Alert],
    sample: &Sample,
    target: u64,
) {
    let active: HashSet<_> = current.iter().map(|alert| alert.code).collect();

    for alert in current.iter().filter(|alert| !previous.contains(alert.code)) {
        let working_set_gib = sample.working_set as f64 / GIB as f64;
        let available_gib = sample.available_ram as f64 / GIB as f64;
        if alert.critical {
            tracing::error!(
                code = alert.code,
                working_set_gib,
                target_gib = target / GIB,
                available_system_ram_gib = available_gib,
                memory_load_percent = sample.memory_load_percent,
                "memory monitor: critical memory pressure"
            );
        } else {
            tracing::warn!(
                code = alert.code,
                working_set_gib,
                target_gib = target / GIB,
                available_system_ram_gib = available_gib,
                memory_load_percent = sample.memory_load_percent,
                "memory monitor: memory pressure warning"
            );
        }
    }

    for recovered in previous.difference(&active) {
        tracing::info!(code = *recovered, "memory monitor: condition recovered");
    }

    *previous = active;
}

fn write_sample(
    writer: &mut BufWriter<std::fs::File>,
    sample: &Sample,
    previous: Option<&Sample>,
    growth: Option<i128>,
    alerts: &[Alert],
) -> std::io::Result<()> {
    let page_fault_delta = previous
        .map_or(0, |old| sample.page_faults.saturating_sub(old.page_faults));
    let working_set_delta = previous
        .map_or(0, |old| signed_delta(sample.working_set, old.working_set));
    let growth = growth.unwrap_or_default();
    let codes = alerts
        .iter()
        .map(|alert| alert.code)
        .collect::<Vec<_>>()
        .join(";");

    macro_rules! optional {
        ($value:expr) => {
            $value.map_or_else(String::new, |value| value.to_string())
        };
    }

    writeln!(
        writer,
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        sample.unix_ms,
        sample.pid,
        sample.working_set,
        optional!(sample.private_working_set),
        sample.peak_working_set,
        sample.private_commit,
        sample.peak_private_commit,
        optional!(sample.shared_commit),
        sample.paged_pool,
        sample.nonpaged_pool,
        sample.page_faults,
        page_fault_delta,
        sample.rust_heap,
        sample.placed_texture_bytes,
        sample.upload_blocks,
        sample.upload_bytes,
        sample.total_ram,
        sample.available_ram,
        sample.memory_load_percent,
        sample.system_commit_total,
        sample.system_commit_limit,
        sample.system_commit_peak,
        sample.system_commit_available,
        optional!(sample.video_local_usage),
        optional!(sample.video_local_budget),
        optional!(sample.video_nonlocal_usage),
        optional!(sample.video_nonlocal_budget),
        working_set_delta,
        growth,
        codes
    )?;
    writer.flush()
}

fn sample_loop(mut writer: BufWriter<std::fs::File>, interval: Duration, target: u64) {
    let mut previous_sample = None;
    let mut previous_alerts = HashSet::new();
    let mut history: VecDeque<(Instant, u64)> = VecDeque::with_capacity(48);
    let mut consecutive_failures = 0u32;

    loop {
        let sampled_at = Instant::now();
        match collect() {
            Ok(sample) => {
                consecutive_failures = 0;
                while history
                    .front()
                    .is_some_and(|(at, _)| sampled_at.duration_since(*at) > Duration::from_secs(12))
                {
                    history.pop_front();
                }

                let growth = growth_over_window(&history, sampled_at, sample.working_set);
                history.push_back((sampled_at, sample.working_set));
                if history.len() > 48 {
                    history.pop_front();
                }

                let alerts = evaluate(&sample, target, growth);
                log_transitions(&mut previous_alerts, &alerts, &sample, target);

                let codes = alerts
                    .iter()
                    .map(|alert| alert.code)
                    .collect::<Vec<_>>()
                    .join(";");
                tracing::debug!(
                    working_set_gib = sample.working_set as f64 / GIB as f64,
                    private_commit_gib = sample.private_commit as f64 / GIB as f64,
                    available_system_ram_gib = sample.available_ram as f64 / GIB as f64,
                    page_faults_delta = previous_sample
                        .map_or(0, |old: Sample| sample.page_faults.saturating_sub(old.page_faults)),
                    alerts = %codes,
                    "memory telemetry sample"
                );

                if let Err(error) = write_sample(
                    &mut writer,
                    &sample,
                    previous_sample.as_ref(),
                    growth,
                    &alerts,
                ) {
                    tracing::error!(%error, "memory telemetry CSV write failed; monitor stopped");
                    break;
                }
                previous_sample = Some(sample);
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures == 1 || consecutive_failures.is_power_of_two() {
                    tracing::error!(
                        %error,
                        consecutive_failures,
                        "memory telemetry sample failed"
                    );
                }
            }
        }

        let elapsed = sampled_at.elapsed();
        std::thread::sleep(interval.saturating_sub(elapsed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(working_set: u64, available_ram: u64, memory_load_percent: u32) -> Sample {
        Sample {
            unix_ms: 0,
            pid: 1,
            working_set,
            peak_working_set: working_set,
            private_working_set: Some(working_set),
            peak_private_commit: working_set,
            shared_commit: Some(0),
            private_commit: working_set,
            paged_pool: 0,
            nonpaged_pool: 0,
            page_faults: 0,
            rust_heap: 0,
            placed_texture_bytes: 0,
            upload_blocks: 0,
            upload_bytes: 0,
            total_ram: 16 * GIB,
            available_ram,
            memory_load_percent,
            system_commit_total: 8 * GIB,
            system_commit_limit: 16 * GIB,
            system_commit_peak: 8 * GIB,
            system_commit_available: 8 * GIB,
            video_local_usage: None,
            video_local_budget: None,
            video_nonlocal_usage: None,
            video_nonlocal_budget: None,
        }
    }

    #[test]
    fn ten_gib_working_set_budget_has_approaching_near_and_exceeded_states() {
        let target = 10 * GIB;
        assert_eq!(evaluate(&sample(7 * GIB, 8 * GIB, 40), target, None), []);
        assert_eq!(evaluate(&sample(8 * GIB, 8 * GIB, 40), target, None)[0].code, "RAM_TARGET_APPROACHING");
        assert_eq!(evaluate(&sample(9 * GIB, 8 * GIB, 40), target, None)[0].code, "RAM_TARGET_NEAR");
        assert_eq!(evaluate(&sample(10 * GIB, 8 * GIB, 40), target, None)[0].code, "RAM_TARGET_EXCEEDED");
    }

    #[test]
    fn low_available_system_ram_is_reported_independently() {
        let alerts = evaluate(&sample(4 * GIB, 900 * MIB, 60), 10 * GIB, None);
        assert!(alerts.iter().any(|alert| alert.code == "SYSTEM_RAM_CRITICAL" && alert.critical));
    }

    #[test]
    fn low_system_commit_is_reported_independently() {
        let mut sample = sample(4 * GIB, 8 * GIB, 60);
        sample.system_commit_available = 900 * MIB;
        let alerts = evaluate(&sample, 10 * GIB, None);
        assert!(alerts.iter().any(|alert| alert.code == "SYSTEM_COMMIT_CRITICAL" && alert.critical));
    }

    #[test]
    fn rapid_resident_growth_is_reported() {
        let alerts = evaluate(&sample(5 * GIB, 8 * GIB, 60), 10 * GIB, Some(512 * MIB));
        assert!(alerts.iter().any(|alert| alert.code == "RAM_GROWTH_SPIKE"));
    }

    #[test]
    fn growth_window_requires_enough_elapsed_time() {
        let now = Instant::now();
        let mut history = VecDeque::new();
        history.push_back((now - Duration::from_secs(9), 2 * GIB));
        history.push_back((now - Duration::from_secs(2), 3 * GIB));
        assert_eq!(growth_over_window(&history, now, 3 * GIB), Some(1_i128 * i128::from(GIB)));
    }
}

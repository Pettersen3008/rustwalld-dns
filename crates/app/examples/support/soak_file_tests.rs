//! Owned local input fixtures; writerless FIFO admission has a process watchdog.
use super::{record, sample, soak_record::bounded_file, soak_samples::Sample, write_sample};
use rustix::fs::{CWD, Mode, mkfifoat};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn regular_input_preserves_empty_exact_and_exceeded_byte_caps() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    fs::write(&input, []).unwrap();
    assert_eq!(bounded_file(&input, 0).unwrap(), b"");
    fs::write(&input, b"complete").unwrap();
    assert_eq!(bounded_file(&input, 8).unwrap(), b"complete");
    assert!(bounded_file(&input, 7).is_err());
    assert!(bounded_file(&input, 0).is_err());
}

#[test]
fn missing_directory_and_symlink_leaves_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    let link = directory.path().join("link");
    assert!(bounded_file(&input, 8).is_err());
    assert!(bounded_file(directory.path(), 8).is_err());
    fs::write(&input, b"complete").unwrap();
    std::os::unix::fs::symlink(&input, &link).unwrap();
    assert!(bounded_file(&link, 8).is_err());
    fs::remove_file(&input).unwrap();
    assert!(bounded_file(&link, 8).is_err());
}

#[test]
fn atomic_regular_sample_replacement_keeps_handoff_valid() {
    let directory = tempfile::tempdir().unwrap();
    let run = record(directory.path(), &["127.0.0.1:9".parse().unwrap()]);
    let before = sample(&run, 0, 10);
    write_sample(&run, &before);
    let observed_before = Sample::read(&run, &run.phases[0]).unwrap();
    assert_eq!(observed_before.sequence, 0);
    assert_eq!(observed_before.counters["requests"], 10);

    let after = sample(&run, 1, 11);
    write_sample(&run, &after);
    let observed_after = Sample::read(&run, &run.phases[0]).unwrap();
    assert_eq!(observed_after.sequence, 1);
    assert_eq!(observed_after.counters["requests"], 11);
    super::soak_samples::continuity(&observed_before, &observed_after).unwrap();
}

#[test]
fn writerless_fifo_is_refused_without_waiting_for_a_writer() {
    const CHILD_TEST: &str =
        "tests::files::writerless_fifo_is_refused_without_waiting_for_a_writer";
    const CHILD_INPUT: &str = "RUSTWALLD_SOAK_FILE_FIFO_TEST_INPUT";
    if let Some(path) = std::env::var_os(CHILD_INPUT) {
        let path = Path::new(&path);
        assert!(bounded_file(path, 16).is_err());
        fs::write(path.with_extension("done"), b"refused").unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("input.fifo");
    mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST])
        .env(CHILD_INPUT, &fifo)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "FIFO child failed: {status}");
                assert_eq!(fs::read(fifo.with_extension("done")).unwrap(), b"refused");
                return;
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("FIFO child exceeded watchdog or failed to wait: {result:?}");
            }
        }
    }
}

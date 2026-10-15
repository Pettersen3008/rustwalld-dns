//! A rejected next-phase observation must not reuse the preceding offer interval.
use super::*;

async fn rejected_entry_preserves_phase_metadata(late_completion: bool) {
    let directory = tempfile::tempdir().unwrap();
    let mut run = record(directory.path(), &["127.0.0.1:9".parse().unwrap()]);
    run.phases[0].qps = 2;
    run.phases[0].deadline_ms = 2000;
    run.limits.latency_us = 2_000_000;
    let mut next = run.phases[0].clone();
    next.id = "later".into();
    next.generations = vec![2];
    run.phases.push(next);
    let prepared = prepare(&run);
    let output = directory.path().join("failed");
    let mut recorder = Recorder::new(&run, &prepared.raw, &output).unwrap();
    write_sample(&run, &sample(&run, 0, 1));
    recorder.begin_phase(0, 1);
    recorder.sample(&run.phases[0]).unwrap();
    // At 2 QPS/2-second deadline, the second exchange can remain pending at 1s.
    recorder.sent(0);
    recorder.sent(0);
    recorder.outcome(
        0,
        Outcome::Reply {
            us: 100,
            wrong: false,
        },
        &run.phases[0],
    );
    let mut pending = [1];
    recorder.flush(&run.phases[0], 1000, &pending).unwrap();

    // The existing generation-1 sample is invalid for the new phase. An empty
    // JoinSet guarantees this control-flow fixture never opens a query socket.
    let mut tasks = JoinSet::new();
    let error = offer_phase(
        &prepared,
        1,
        &mut recorder,
        &mut tasks,
        &mut pending,
        &CancellationToken::new(),
        Schedule {
            start: Instant::now() - Duration::from_secs(1),
            ordinal_base: 2,
            seconds_base: 1,
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("collector identity"));
    assert!(tasks.is_empty());
    assert_eq!(pending, [1]);
    if late_completion {
        recorder.outcome(
            0,
            Outcome::Reply {
                us: 5,
                wrong: false,
            },
            &run.phases[0],
        );
    } else {
        recorder.cancel(&pending);
    }
    let report = recorder
        .finish(&run.phases[1], 1000, Some(error.to_string()), false)
        .unwrap();
    assert_eq!(report["driver_passed"], false);
    assert_eq!(report["completed"], false);
    assert_eq!(report["accounting_reconciled"], true);
    assert_eq!(report["counts"]["sent"], 2);
    assert_eq!(report["counts"]["cancelled"], u64::from(!late_completion));
    assert_eq!(report["failure"], error.to_string());
    let rows: Vec<Value> = std::fs::read_to_string(output.join("windows.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    let failed = &rows[1];
    assert_eq!(failed["phase"], "later");
    assert_eq!(failed["offer_start_ms"], 1000);
    assert_eq!(failed["offer_end_ms"], 2000);
    assert_eq!(failed["counts"]["sent"], 0);
    assert_eq!(failed["counts"]["offered"], 0);
    assert_eq!(failed["resources"]["samples"], 0);
    assert_eq!(failed["resources"]["last"], Value::Null);
    assert_eq!(failed["last_generation"], 1);
    assert_eq!(
        failed["completed_phase_counts"],
        if late_completion {
            json!({"steady":1})
        } else {
            json!({})
        }
    );
}

#[tokio::test]
async fn rejected_phase_entry_cancels_pending_work_under_the_new_interval() {
    rejected_entry_preserves_phase_metadata(false).await;
}

#[tokio::test]
async fn rejected_phase_entry_keeps_late_completion_origin_under_the_new_interval() {
    rejected_entry_preserves_phase_metadata(true).await;
}

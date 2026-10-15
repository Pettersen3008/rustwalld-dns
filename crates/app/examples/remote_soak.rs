//! Read-only bounded load on explicitly configured private endpoints. No service activation.
use clap::Parser;
use serde_json::{Value, json};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval_at, sleep_until},
};
use tokio_util::sync::CancellationToken;
#[path = "support/histogram.rs"]
mod histogram;
#[path = "support/soak_probe.rs"]
mod soak_probe;
#[path = "support/soak_record.rs"]
mod soak_record;
#[path = "support/soak_recorder.rs"]
mod soak_recorder;
#[path = "support/soak_samples.rs"]
mod soak_samples;
use soak_probe::Outcome;
use soak_record::{Phase, Prepared, invalid};
use soak_recorder::Recorder;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    run: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
    /// Validate the entire record without opening sockets, reading samples or creating output.
    #[arg(long)]
    validate_only: bool,
}
fn lane_at(run: &soak_record::Run, index: u64) -> usize {
    let total: u64 = run.lanes.iter().map(|l| u64::from(l.weight)).sum();
    let mut pos = index % total;
    for (i, lane) in run.lanes.iter().enumerate() {
        if pos < u64::from(lane.weight) {
            return i;
        }
        pos -= u64::from(lane.weight);
    }
    0 // Validated nonempty lanes and positive weights make the loop exhaustive.
}
type Exchange = (usize, usize, Outcome);
fn complete(
    result: Result<Exchange, tokio::task::JoinError>,
    pending: &mut [u64],
    recorder: &mut Recorder,
    phases: &[Phase],
) -> Option<String> {
    match result {
        Ok((lane, origin, outcome)) => {
            pending[lane] -= 1;
            recorder
                .outcome(lane, outcome, &phases[origin])
                .map(|reason| format!("{reason}: lane {lane}, phase {}", phases[origin].id))
        }
        Err(_) => Some("query task failed".into()),
    }
}
struct Schedule {
    start: Instant,
    ordinal_base: u64,
    seconds_base: u64,
}
fn slot_offset(index: u64, qps: u32) -> Duration {
    // At 72h/100k QPS the product exceeds u64 even though the quotient fits.
    Duration::from_nanos((u128::from(index) * 1_000_000_000 / u128::from(qps)) as u64)
}
async fn offer_phase(
    prepared: &Prepared,
    origin: usize,
    recorder: &mut Recorder,
    tasks: &mut JoinSet<Exchange>,
    pending: &mut [u64],
    cancel: &CancellationToken,
    schedule: Schedule,
) -> io::Result<()> {
    let start = schedule.start;
    let phase = &prepared.record.phases[origin];
    let phase_start = start + Duration::from_secs(schedule.seconds_base);
    recorder.begin_phase(
        phase_start.duration_since(start).as_millis() as u64,
        phase.seconds,
    );
    recorder.sample(phase)?;
    let end = phase_start + Duration::from_secs(phase.seconds);
    let mut samples = interval_at(phase_start + Duration::from_secs(1), Duration::from_secs(1));
    let mut windows = interval_at(
        phase_start + Duration::from_secs(60),
        Duration::from_secs(60),
    );
    samples.set_missed_tick_behavior(MissedTickBehavior::Skip);
    windows.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let (mut index, mut interval_done) = (0u64, false);
    let total = phase.seconds * u64::from(phase.qps);
    while index < total || !interval_done {
        let at = phase_start + slot_offset(index, phase.qps);
        tokio::select! {
            biased;
            ()=cancel.cancelled()=>return Err(invalid("cancelled")),
            scheduled=samples.tick()=>{
                if scheduled.elapsed()>=Duration::from_secs(1) { return Err(invalid("missing resource sampling interval")); }
                recorder.sample(phase)?;
            }
            scheduled=windows.tick()=>{
                // Only the last offered minute owns the final bounded drain.
                if scheduled<end { recorder.flush(phase,start.elapsed().as_millis() as u64,pending)?; }
            }
            Some(result)=tasks.join_next(), if !tasks.is_empty()=>{
                if let Some(reason)=complete(result,pending,recorder,&prepared.record.phases) { return Err(invalid(reason)); }
            }
            ()=sleep_until(at), if index<total=>{
                let now=Instant::now();
                if now.saturating_duration_since(at)>Duration::from_millis(phase.max_lag_ms)
                    || tasks.len()>=prepared.record.limits.outstanding {
                    let due=(now.duration_since(phase_start).as_nanos()*u128::from(phase.qps)/1_000_000_000+1).min(u128::from(total)) as u64;
                    recorder.skipped(index,due.saturating_sub(index).max(1));
                    return Err(invalid("missed offered load"));
                }
                let lane=lane_at(&prepared.record,index);
                recorder.sent(lane); pending[lane]+=1;
                let l=prepared.record.lanes[lane].clone();
                let bind=prepared.record.clients[l.client].bind;
                let templates=prepared.templates[lane].clone();
                let accepted=phase.accepted.clone();
                let ordinal=schedule.ordinal_base+index; let deadline=phase.deadline_ms;
                let seed=prepared.record.seed;
                tasks.spawn(async move { (lane,origin,soak_probe::probe(bind,l,templates,accepted,ordinal,deadline,seed).await) });
                index+=1;
            }
            ()=sleep_until(end), if !interval_done=>interval_done=true,
        }
    }
    recorder.sample(phase)?;
    if origin + 1 < prepared.record.phases.len() {
        recorder.flush(phase, start.elapsed().as_millis() as u64, pending)?;
    }
    Ok(())
}
async fn drain(
    prepared: &Prepared,
    phase: &Phase,
    recorder: &mut Recorder,
    tasks: &mut JoinSet<Exchange>,
    pending: &mut [u64],
    cancel: &CancellationToken,
) -> io::Result<()> {
    let mut samples = interval_at(
        Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    while !tasks.is_empty() {
        tokio::select! { biased;
            ()=cancel.cancelled()=>return Err(invalid("cancelled")),
            scheduled=samples.tick()=>{
                if scheduled.elapsed()>=Duration::from_secs(1) {return Err(invalid("missing drain sampling interval"));}
                recorder.sample(phase)?;
            },
            Some(result)=tasks.join_next()=>{
                if let Some(reason)=complete(result,pending,recorder,&prepared.record.phases) {return Err(invalid(reason));}
            }
        }
    }
    recorder.sample(phase)
}
async fn drive(prepared: Prepared, output: &Path, cancel: CancellationToken) -> io::Result<Value> {
    let mut recorder = Recorder::new(&prepared.record, &prepared.raw, output)?;
    let mut tasks = JoinSet::new();
    let mut pending = vec![0; prepared.record.lanes.len()];
    let mut failure = recorder
        .sample(&prepared.record.phases[0])
        .err()
        .map(|e| e.to_string());
    let start = Instant::now();
    let mut ordinal_base = 0;
    let mut seconds_base = 0;
    let mut last_phase = &prepared.record.phases[0];
    for (origin, phase) in prepared.record.phases.iter().enumerate() {
        if failure.is_some() {
            break;
        }
        last_phase = phase;
        if let Err(error) = offer_phase(
            &prepared,
            origin,
            &mut recorder,
            &mut tasks,
            &mut pending,
            &cancel,
            Schedule {
                start,
                ordinal_base,
                seconds_base,
            },
        )
        .await
        {
            failure = Some(error.to_string());
            break;
        }
        ordinal_base += phase.seconds * u64::from(phase.qps);
        seconds_base += phase.seconds;
    }
    if failure.is_none()
        && let Err(error) = drain(
            &prepared,
            last_phase,
            &mut recorder,
            &mut tasks,
            &mut pending,
            &cancel,
        )
        .await
    {
        failure = Some(error.to_string());
    }
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        if result.is_ok()
            && let Some(reason) =
                complete(result, &mut pending, &mut recorder, &prepared.record.phases)
        {
            failure.get_or_insert(reason);
        }
    }
    recorder.cancel(&pending);
    recorder.finish(
        last_phase,
        start.elapsed().as_millis() as u64,
        failure.clone(),
        failure.is_none(),
    )
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let prepared = Prepared::load(&args.run)?;
    if args.validate_only {
        println!("{}", json!({"valid":true,"run_id":prepared.record.run_id}));
        return Ok(());
    }
    let output = args
        .output
        .ok_or_else(|| invalid("--output NEW_DIRECTORY required"))?;
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let handler = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    let result = drive(prepared, &output, cancel).await;
    handler.abort();
    let _ = handler.await;
    let report = result?;
    println!(
        "{}",
        json!({"run_id":report["run_id"],"driver_passed":report["driver_passed"],"failure":report["failure"]})
    );
    if report["driver_passed"] != true {
        return Err(invalid(
            "driver acceptance failed; inspect preserved summary.json",
        ));
    }
    Ok(())
}
#[cfg(test)]
#[path = "support/soak_tests.rs"]
mod tests;

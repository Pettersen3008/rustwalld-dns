import { useQuery } from "@tanstack/react-query";
import type { Api, Configuration } from "@/lib/api";
import { Badge, ErrorNotice, Field } from "@/components/common";
type Schedule = NonNullable<
  NonNullable<Configuration["policies"][number]["blocked_services"]>["schedule"]
>;
const days = [
  ["mon", "Monday"],
  ["tue", "Tuesday"],
  ["wed", "Wednesday"],
  ["thu", "Thursday"],
  ["fri", "Friday"],
  ["sat", "Saturday"],
  ["sun", "Sunday"],
] as const;
const wholeDay = () => ({ days: days.map(([id]) => id), start: "00:00", end: "24:00" });
export function ServiceScheduleEditor({
  api,
  draft,
  index,
  edit,
}: {
  api: Api;
  draft: Configuration;
  index: number;
  edit: (value: Configuration) => void;
}) {
  const policy = draft.policies[index]!;
  const settings = policy.blocked_services;
  const schedule = settings?.schedule;
  const live = useQuery({
    queryKey: ["service-schedule-status"],
    queryFn: ({ signal }) =>
      api
        .request<
          {
            name: string;
            service_schedule?: {
              state: "active" | "inactive" | "invalid_clock";
              time_zone: string;
              ttl_cap: number;
              tzdb_version?: string;
            } | null;
          }[]
        >("/api/v1/policies", { signal })
        .then((response) => response.value),
    refetchInterval: 5000,
  });
  const publishedPolicy = live.data?.find((entry) => entry.name === policy.name);
  const published = publishedPolicy?.service_schedule;
  function update(value: Schedule | undefined) {
    if (!settings?.ids.length) return;
    edit({
      ...draft,
      policies: draft.policies.map((entry, i) =>
        i === index ? { ...entry, blocked_services: { ...settings, schedule: value } } : entry,
      ),
    });
  }
  function windowAt(i: number, patch: Partial<Schedule["windows"][number]>) {
    if (schedule)
      update({
        ...schedule,
        windows: schedule.windows.map((entry, j) => (j === i ? { ...entry, ...patch } : entry)),
      });
  }
  return (
    <section className="service-schedule" aria-label="Weekly service schedule">
      <div className="panel-head">
        <div>
          <h3>Weekly schedule</h3>
          <p>Local clock hours in an explicit time zone. These choices stay in the draft.</p>
        </div>
        <Badge>{schedule ? "WEEKLY IN DRAFT" : "NO DRAFT SCHEDULE"}</Badge>
      </div>
      <label className="service-choice">
        <input
          type="checkbox"
          aria-label="Use weekly service schedule"
          checked={!!schedule}
          disabled={!settings?.ids.length}
          onChange={(event) =>
            update(
              event.target.checked
                ? { time_zone: "UTC", mode: "block", windows: [wholeDay()] }
                : undefined,
            )
          }
        />
        <span>Use weekly service schedule</span>
      </label>
      {!settings?.ids.length && (
        <p className="body-copy">Select a service to configure its schedule.</p>
      )}
      {schedule && (
        <>
          <div className="form-grid">
            <Field
              label="Schedule time zone"
              hint="IANA name, such as Europe/Oslo. Local is not accepted."
            >
              <input
                value={schedule.time_zone}
                list="service-schedule-zones"
                onChange={(event) => update({ ...schedule, time_zone: event.target.value })}
              />
              <datalist id="service-schedule-zones">
                {[
                  "UTC",
                  "Europe/Oslo",
                  "Europe/London",
                  "America/New_York",
                  "America/Los_Angeles",
                  "Asia/Tokyo",
                  "Australia/Sydney",
                ].map((zone) => (
                  <option key={zone} value={zone}>
                    {zone}
                  </option>
                ))}
              </datalist>
            </Field>
            <Field label="Schedule mode">
              <select
                value={schedule.mode}
                onChange={(event) =>
                  update({ ...schedule, mode: event.target.value as Schedule["mode"] })
                }
              >
                <option value="block">Block during these hours</option>
                <option value="allow">Allow during these hours; block otherwise</option>
              </select>
            </Field>
          </div>
          {schedule.windows.map((window, i) => (
            <div className="schedule-window" key={i}>
              <div className="panel-head">
                <strong>Window {i + 1}</strong>
                <button
                  aria-label={`Remove schedule window ${i + 1}`}
                  onClick={() =>
                    update({ ...schedule, windows: schedule.windows.filter((_, j) => j !== i) })
                  }
                >
                  Remove
                </button>
              </div>
              <div className="schedule-days">
                {days.map(([id, name]) => (
                  <label key={id}>
                    <input
                      type="checkbox"
                      aria-label={`Window ${i + 1} ${name}`}
                      checked={window.days.includes(id)}
                      onChange={(event) =>
                        windowAt(i, {
                          days: event.target.checked
                            ? [...window.days, id]
                            : window.days.filter((day) => day !== id),
                        })
                      }
                    />
                    {name.slice(0, 3)}
                  </label>
                ))}
              </div>
              <div className="form-grid">
                <Field label={`Window ${i + 1} start`} hint="HH:MM, 00:00–23:59">
                  <input
                    value={window.start}
                    maxLength={5}
                    onChange={(event) => windowAt(i, { start: event.target.value })}
                  />
                </Field>
                <Field
                  label={`Window ${i + 1} end`}
                  hint="HH:MM; 24:00 includes the rest of the day"
                >
                  <input
                    value={window.end}
                    maxLength={5}
                    onChange={(event) => windowAt(i, { end: event.target.value })}
                  />
                </Field>
              </div>
            </div>
          ))}
          <button
            onClick={() => update({ ...schedule, windows: [...schedule.windows, wholeDay()] })}
            disabled={schedule.windows.length >= 32}
          >
            Add schedule window
          </button>
          {!schedule.windows.length && (
            <p className="notice">
              No windows: selected service groups are{" "}
              {schedule.mode === "block" ? "never blocked by this schedule" : "always blocked"}.
              Other filters keep applying.
            </p>
          )}
          <p className="body-copy">
            Start is included, end is excluded. Overnight windows continue into the next day;
            overlaps combine. Repeated DST hours apply twice and skipped hours do not occur.
            Temporary allows and filtering pauses keep their overrides. Permanent assertions ignore
            schedules.
          </p>
          <details>
            <summary>DNS cache and clock limits</summary>
            <p className="body-copy">
              Scheduled policies cap new replies at the next minute boundary. Older client answers,
              other resolvers and wall-clock jumps cannot be recalled. In-flight transitions may
              return SERVFAIL for retry. Keep the appliance clock synchronized; a clock outside
              2000–2099 enforces the service groups with TTL zero.
            </p>
          </details>
        </>
      )}
      <ErrorNotice error={live.error} retry={() => void live.refetch()} />
      {live.data && (
        <p className="body-copy">
          Published policy:{" "}
          {published
            ? `${published.state} · ${published.time_zone}${published.tzdb_version ? ` · tzdb ${published.tzdb_version}` : ""}`
            : publishedPolicy
              ? "no weekly service schedule"
              : "this draft policy is not published"}
          . Live status describes the published policy, separate from draft settings.
        </p>
      )}
    </section>
  );
}

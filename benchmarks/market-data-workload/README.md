# C-103 synthetic market data workload

This directory defines and measures one local stage. The source is a seeded,
normalized NDJSON file. The reader streams the file, parses and checks each
envelope, computes the `event_id` dedupe key, enqueues eligible unique events in
a bounded in-process FIFO, and records the consumer ACK. It does not measure a
provider adapter, network publish, durable write or strategy replay.

## Profile and evidence

`workload.schema.json` is `leviathan.workload/1`. The programmatic validator
interprets its structural/type/range rules and adds cross-field checks for mix
sums, ordered distributions, count/rate/duration consistency, sequence-gap
declaration, full serialized envelope size and synthetic/acceptance classification.
The validator and generator use the same `envelope.py` serializer and 64 KiB
line limit, including the newline. Validation preflights each event type's
maximum payload with worst-case identifiers. `UNRESOLVED` anywhere in
an acceptance profile is a blocking error. The acceptance template is meant to
fail until representative data and the operator's choices are supplied.
Profile and manifest JSON parse decimal numbers without binary-float rounding.
Every JSON number is limited to 34 significant digits. All declared lateness,
exchange clock skew and late thresholds are converted from their exact decimal
millisecond spelling to **integer nanoseconds**. Values requiring less than one
nanosecond of precision fail validation; no fractional millisecond value is
truncated. The reader compares integer nanosecond
differences with the threshold and checks exchange skew against the declaration.
The rate-times-duration product must fit the 100,000-event slice before
rounding, and manifest counters must be nonnegative JSON integers (not booleans).

`profiles/synthetic-v1.json` is a **nonacceptance** profile for the stated
16 GiB Windows PC. It declares 100,000 unique events at a nominal 50,000/s
for two seconds, with seven event types, 64 instruments, two venues, two
channels, 1% intentional duplicates, 0.5% late events and 0.1% gap insertions.
The generator adds duplicate lines, so generated line count is 101,000. Events
are streamed and never retained as one dataset in RAM. A benchmark run is capped
at 100,000 unique events and a planned peak RSS below 1.5 GiB. The included
profile reaches that event ceiling. A larger profile needs a later contract.
The file reader is **unpaced**: the profile
rate, duration and burst fields describe the synthetic workload, while the
benchmark reports achieved throughput of the local file-fed stage. It does not
claim sustained delivery at the nominal rate or exercise the burst schedule.

The manifest records SHA-256 over exact NDJSON bytes, byte/line/unique counts,
exact intentional gap ranges per `(venue, instrument_id, channel)`, late keys,
rejected late keys and eligible unique count. The reader rejects missing or
extra lines, changed bytes, malformed envelopes, unexpected sequence gaps,
undeclared late events and mismatched counters. Declared gaps represent events
that were never generated. Duplicates and policy-rejected late events are
separate counters and never count as eligible loss.

The reader binds the manifest's unique count and its observed distinct record
count to `traffic.event_count`. Even a new valid record with a matching edited
manifest fails when it exceeds the profile's declared event count.
Before dedupe or enqueue, the reader rejects nonstandard JSON nonfinite tokens,
checks the required payload fields and their JSON types for the event type,
allows only the optional string `padding` field, enforces the profile's per-type
maximum payload bytes, and rejects invalid timestamps.

`eligible_unique` is the number of distinct schema-valid keys after late-policy
rejection and dedupe. `unique_acked` is the number with consumer ACK. `loss_count`
is `eligible_unique - unique_acked`; `loss_rate` divides by `eligible_unique`,
and a zero denominator fails. Enqueue-to-ACK time starts immediately before
the bounded queue `put`, including any block time, and ends when the consumer
reads the item and ACKs. Parse, validation and dedupe are outside that latency.
Whole-pipeline throughput starts at reader entry and ends at final ACK.
Steady-state throughput divides ACKs after warmup by the measured seconds after
warmup. Percentiles use nearest-rank samples of ACKed events only.

## Run from the repository root

The worktree is separate from the project control plane, so use an absolute
QA output directory on this host:

```powershell
$qa = 'C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\qa\benchmarks\market-data-workload'
$profile = 'benchmarks/market-data-workload/profiles/synthetic-v1.json'
uv run python benchmarks/market-data-workload/validate.py --profile $profile
uv run python benchmarks/market-data-workload/generate.py --profile $profile --output "$qa/synthetic-v1.ndjson" --manifest "$qa/synthetic-v1.manifest.json"
uv run python benchmarks/market-data-workload/bench.py --profile $profile --input "$qa/synthetic-v1.ndjson" --manifest "$qa/synthetic-v1.manifest.json" --report "$qa/local-stage-report.json"
uv run pytest benchmarks/market-data-workload/tests -q
```

The benchmark also writes `local-stage-report.md` beside the JSON report. Run
the generator again with a second output and manifest path and compare SHA-256
of the two NDJSON files to verify deterministic seed and index generation.
Each benchmark report is a single-run observation. Run the benchmark at least
three times sequentially on the same file, then report unweighted median,
minimum and maximum for throughput and enqueue-to-ACK p99, with the host-load
conditions. Do not present one timing run as the benchmark result.

The report labels are fixed: `pipeline=local_parse_dedupe_to_in_process_ack`,
`latency_boundary=enqueue_to_ack`, `durability=none`,
`dataset_class=synthetic`, `prd_target_verified=false`.

The three PRD performance gates remain distinct and unverified:

| Gate | Target | Missing boundary evidence |
|---|---|---|
| Storage | >=200,000 events/s/node and p99 write ACK <15 ms | Durable store write ACK on representative mix and chosen hardware |
| Ingestion | >=250,000 events/s/shard and p99 ingest-to-publish <=15 ms WS / <=100 ms REST | Adapter, shard and network publication |
| Replay | >=2,000,000 ticks/s/worker | Tick workload and strategy replay worker |

No result here selects a hot tier or establishes Cloudflare, Neon or R2 capacity.

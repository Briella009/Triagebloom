# Performance benchmark protocol

This document defines the runtime and memory experiment for the AISCN 2027 TriageBloom study.

The benchmark implementation is `scripts/research_performance_benchmark.py`.

## What is measured

For each requested event count, the benchmark separates:

- **ingest time** — reading/decompressing the selected COMISET stream, adapting fields and normalising events;
- **detection time** — executing TriageBloom rules over the already normalised event list;
- **end-to-end time** — ingest plus detection inside the worker process;
- **detection throughput** — events per second during rule execution;
- **end-to-end throughput** — events per second across ingest and detection;
- **peak RSS / peak working set** — the process-level memory high-water mark.

The benchmark does not use `tracemalloc` as the manuscript memory measure because Python allocation tracking is not equivalent to total process resident memory.

## Isolation

Every measured repetition executes in a fresh child process. This prevents a larger earlier run from permanently inflating the peak-RSS value recorded for a smaller later run.

On Windows, peak memory uses the operating system `PeakWorkingSetSize`. On Linux and other supported Unix-like systems, it uses `getrusage(RUSAGE_SELF).ru_maxrss` with platform-specific unit conversion.

## Default study sizes

The default command measures:

- 10,000 events;
- 100,000 events;
- 1,000,000 events.

If the selected data member contains fewer events, the benchmark fails rather than silently reporting a smaller sample under the requested label.

Larger event counts may be added if the study machine can execute them reliably, but the originally reported sizes must not be dropped simply because one result is unfavourable.

## Repetitions

For each event count:

1. execute one warm-up run;
2. discard the warm-up result from the reported summary;
3. execute five measured runs;
4. report the median and interquartile range;
5. retain all measured trial values in the JSON output.

The warm-up intentionally allows code and filesystem caches to reach a steady state. The manuscript should state that the published medians are warm-cache measurements if this default procedure is used.

## Primary command

```bash
python scripts/research_performance_benchmark.py benchmark \
  evaluation/external/Comiset23_Lab_Environment_Dataset.zip \
  --member '<DATA_MEMBER>' \
  --profile balanced \
  --sizes 10000 100000 1000000 \
  --warmups 1 \
  --repetitions 5 \
  --output evaluation/external/performance-balanced.json
```

The event stream prefix must be the same across repetitions of a given size. Do not select a faster or easier subset after viewing results.

## Required environment record

The final experiment record must additionally capture, outside the script where necessary:

- CPU model;
- installed RAM;
- storage type if known;
- power mode / whether the laptop is plugged in;
- operating system version;
- Python version;
- TriageBloom commit SHA.

The script records the available OS/Python/processor metadata and commit SHA automatically, but some Windows firmware/hardware fields may require a manual note.

## What the results can support

A successful benchmark can support claims such as:

> On the documented test machine, TriageBloom processed N normalised events at a median rule-execution throughput of X events/s with a median peak process working set of Y MiB across five measured runs.

It cannot by itself support claims that TriageBloom is cheaper, faster or more resource-efficient than Sentinel, Defender, an LLM, a graph system or another research tool unless the comparison is measured under an equivalent experimental setup.

## Interpreting ingest versus detection

The primary engineering question is deliberately split in two.

A compressed COMISET archive may be limited by ZIP decompression and storage throughput rather than TriageBloom rule execution. Reporting only end-to-end throughput could therefore attribute dataset-I/O cost to the detection engine.

Conversely, reporting only detection time would hide the practical cost of adapting real external telemetry. The final paper should show both.

## Reproducibility

Do not publish benchmark numbers unless all of the following are preserved:

- official dataset/version;
- archive hash;
- archive member;
- exact TriageBloom commit;
- profile/configuration;
- event count;
- warm-up count;
- number of measured repetitions;
- individual trial results;
- median and IQR;
- study-machine specification.

## Research boundary

The benchmark is a performance characterization of TriageBloom on a documented machine. It is not a production scalability guarantee and does not establish latency under a live SIEM ingestion workload.

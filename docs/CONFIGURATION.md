# Configuration

TriageBloom ships with three built-in rule profiles and also accepts a JSON configuration file for transparent threshold tuning, allow-lists, and rule suppression.

## Built-in profiles

Use a profile with `--profile`:

```bash
triagebloom analyze logs.json --profile learner
triagebloom analyze logs.json --profile balanced
triagebloom analyze logs.json --profile strict
```

- `learner`: lower thresholds for demonstrations and training.
- `balanced`: default thresholds for general controlled testing.
- `strict`: higher thresholds intended to reduce noise.

Profiles are starting points, not validated production baselines. Tune them against authorised data and record every change used in an evaluation.

## JSON configuration

Copy `config.example.json` and edit only the values you understand.

```bash
triagebloom analyze logs.json --config my-config.json --output-dir reports
```

Supported fields:

| Field | Meaning | Default |
|---|---|---:|
| `spray_users` | Distinct users required for password-spray detection | 5 |
| `spray_window_minutes` | Password-spray time window | 10 |
| `brute_force_failures` | Failed sign-ins against one account | 8 |
| `brute_force_window_minutes` | Brute-force time window | 10 |
| `success_after_failures` | Failures required before a successful sign-in is escalated | 5 |
| `success_window_minutes` | Failure-to-success time window | 15 |
| `mfa_failures` | MFA-related failures required before a later success is escalated | 4 |
| `mfa_window_minutes` | MFA-fatigue time window | 15 |
| `correlation_window_minutes` | Window for authentication-to-endpoint incident correlation | 30 |
| `business_start_hour` | Start of configured business hours in UTC | 7 |
| `business_end_hour` | End of configured business hours in UTC | 20 |
| `enable_off_hours` | Enable low-severity off-hours success findings | true |
| `allow_users` | Exact user identifiers whose findings may be suppressed | [] |
| `allow_source_ips` | Exact source IPs whose findings may be suppressed | [] |
| `allow_devices` | Exact device names whose findings may be suppressed | [] |
| `suppressed_rule_ids` | Rule IDs to disable | [] |

## CLI overrides

Selected thresholds can be overridden directly:

```bash
triagebloom analyze logs.json \
  --spray-users 7 \
  --spray-window 15 \
  --mfa-failures 5 \
  --correlation-window 45
```

CLI overrides are applied after the selected profile and JSON configuration.

## Allow-list warning

An allow-list can hide malicious behaviour if it is too broad or stale. Treat allow-list entries as security-sensitive configuration:

- use exact identifiers rather than broad patterns;
- review them regularly;
- document why each entry exists;
- do not allow-list an entity merely because it creates noisy findings;
- preserve an unfiltered copy of the source data for investigation.

## Reproducibility

For any benchmark, pilot, paper, or public result, record:

- TriageBloom version or commit hash;
- selected profile;
- full configuration file;
- command-line overrides;
- Python version;
- dataset version and checksum.

This makes threshold-dependent results auditable instead of presenting them as universal performance claims.

# Input data guide

## Minimum requirement

Every event must contain a timestamp. Useful detections also need some combination of user, source IP, outcome, device, event type, and command line.

## CSV example

```csv
timestamp,event_id,event_type,outcome,user,source_ip,device
2026-08-10T21:00:00Z,evt-1,SignIn,Failure,user@example.org,203.0.113.50,LAPTOP-01
```

## JSON example

```json
[
  {
    "createdDateTime": "2026-08-10T21:00:00Z",
    "id": "evt-1",
    "activityDisplayName": "User login",
    "resultType": "50126",
    "userPrincipalName": "user@example.org",
    "ipAddress": "203.0.113.50"
  }
]
```

## JSON wrappers

The reader accepts a top-level object containing an event array under any of these keys:

- `events`
- `records`
- `value`
- `data`

## Timestamp formats

Supported timestamp forms include:

- ISO 8601 with `Z`
- ISO 8601 with an explicit offset
- common `YYYY-MM-DD HH:MM:SS` forms
- epoch seconds
- epoch milliseconds

Naive timestamps are treated as UTC. For reliable off-hours analysis, export timestamps with an explicit zone.

## Outcome normalisation

Common success values include `0`, `success`, `succeeded`, `allowed`, and `true`.

Common failure values include `failure`, `failed`, `denied`, `blocked`, and non-zero numeric result codes.

When no clear value exists, the normaliser may infer an outcome from the event type. Unknown values remain `unknown`.

## Safe fixture policy

Only commit synthetic or authorised sanitised examples. Replace real names, email addresses, IP addresses, device names, tenant IDs, URLs, tokens, hashes, and case identifiers before publishing data.

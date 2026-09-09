# Input data guide

## Minimum requirement

Every event must contain a timestamp. Useful detections also need some combination of user, source IP, outcome, device, event type, command line, and Microsoft-specific security context.

## Generic CSV example

```csv
timestamp,event_id,event_type,outcome,user,source_ip,device
2026-08-10T21:00:00Z,evt-1,SignIn,Failure,user@example.org,203.0.113.50,LAPTOP-01
```

## Microsoft Entra ID example

```json
{
  "createdDateTime": "2026-08-10T10:00:00Z",
  "id": "evt-1",
  "activityDisplayName": "User sign-in",
  "resultType": "0",
  "userPrincipalName": "user@example.org",
  "ipAddress": "203.0.113.5",
  "conditionalAccessStatus": "success",
  "riskLevelDuringSignIn": "none",
  "authenticationRequirement": "multiFactorAuthentication"
}
```

## Microsoft Defender process example

```json
{
  "Timestamp": "2026-08-10T10:05:00Z",
  "ReportId": "proc-1",
  "DeviceName": "LAPTOP-01",
  "ActionType": "ProcessCreated",
  "AccountName": "user@example.org",
  "FileName": "powershell.exe",
  "ProcessCommandLine": "powershell.exe -NoProfile",
  "InitiatingProcessFileName": "explorer.exe",
  "SHA256": "..."
}
```

## JSON wrappers

The reader accepts a top-level object containing an event array under:

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

Naive timestamps are treated as UTC.

## Outcome normalisation

Common success values include `0`, `success`, `succeeded`, `allowed`, and `true`.

Common failure values include `failure`, `failed`, `denied`, `blocked`, and non-zero numeric Microsoft result codes.

When present, Microsoft Entra `status.errorCode` is also considered.

## Safe fixture policy

Only commit synthetic or authorised sanitised examples. Replace real names, email addresses, IP addresses, device names, tenant IDs, URLs, tokens, hashes, case identifiers, and organisation identifiers before publishing data.

## Microsoft-aware fields

When available, the normalised model preserves selected context from Microsoft Entra ID and Microsoft Defender exports, including Conditional Access status, sign-in risk, authentication requirement or method details, parent or initiating process, file name, SHA256, and Defender alert metadata.

See `MICROSOFT_ADAPTERS.md` for the supported subset and limitations.

## Source products

Events are labelled as `generic`, `microsoft_entra`, `microsoft_defender`, or `microsoft_defender_alert` when the input shape provides enough evidence for recognition. Source recognition is heuristic and should be verified when onboarding a new export schema.

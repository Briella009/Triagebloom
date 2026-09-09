# Microsoft security adapters

TriageBloom 0.2.0 recognises selected Microsoft Entra ID and Microsoft Defender export fields and maps them into the same vendor-neutral event model used by generic inputs.

The adapters are intentionally lightweight. They do not call Microsoft Graph, Microsoft Sentinel, Defender APIs, or any cloud service.

## Microsoft Entra ID sign-ins

TriageBloom identifies an event as Microsoft Entra-style when common sign-in fields such as `createdDateTime`, `userPrincipalName`, and authentication or risk context are present.

Supported context includes, where exported:

- `createdDateTime`
- `id`
- `userPrincipalName`
- `ipAddress`
- `resultType`
- nested `status.errorCode`
- `conditionalAccessStatus`
- `riskLevelDuringSignIn`
- `riskLevelAggregated`
- `riskState`
- `authenticationRequirement`
- `authenticationDetails`
- `appDisplayName`
- `resourceDisplayName`
- `clientAppUsed`
- `deviceDetail`
- `location`

These fields enrich findings such as success-after-failures and MFA-fatigue analysis. TriageBloom does not recreate Microsoft risk scoring and does not treat a Microsoft risk label as proof of compromise.

## Microsoft Defender process events

TriageBloom recognises Defender-style endpoint process records when fields such as `DeviceName`, `ProcessCommandLine`, `InitiatingProcessFileName`, or `ActionType` are present.

Supported context includes:

- `Timestamp`
- `ReportId`
- `DeviceName`
- `ActionType`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `InitiatingProcessAccountName`
- `ProcessId`
- `FolderPath`
- `SHA256`

The process adapter supplies context to suspicious PowerShell, LOLBin, and cross-event correlation rules.

## Microsoft Defender alerts

TriageBloom recognises alert-style records using fields such as:

- `AlertId`
- `Title`
- `Severity`
- `Category`
- `ServiceSource`
- `DetectionSource`
- `DeviceName`
- `AccountName`

Defender alerts are currently normalised for context and reporting. TriageBloom does not duplicate every upstream Defender alert as a new local detection because doing so would inflate finding counts and make evaluation misleading.

## Source recognition

Normalised events include a `source_product` value such as:

- `microsoft_entra`
- `microsoft_defender`
- `microsoft_defender_alert`
- `generic`

The analysis report records the source products observed in the input.

## Important limitations

Microsoft schemas can change and export shapes vary between portals, APIs, Advanced Hunting tables, and customer configurations. TriageBloom therefore supports a documented subset rather than claiming universal Microsoft compatibility.

Before using a new export shape:

1. work with authorised or synthetic data;
2. inspect whether the required fields are present;
3. add a sanitised fixture if the schema is safe to share;
4. add an automated test before changing the adapter;
5. document any unsupported nested or table-specific fields.

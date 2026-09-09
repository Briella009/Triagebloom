# Technical references

TriageBloom uses public vendor documentation and MITRE ATT&CK as implementation references. These links are included for traceability; the project is not affiliated with Microsoft or MITRE.

## Microsoft

- Microsoft Graph `signIn` resource: https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0
- Microsoft Defender XDR `DeviceProcessEvents` advanced hunting schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table

Microsoft export shapes can vary by API, portal, table, licensing tier, and product version. TriageBloom supports a documented subset rather than claiming universal compatibility.

## MITRE ATT&CK

- T1110.001 Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- T1110.003 Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- T1621 Multi-Factor Authentication Request Generation: https://attack.mitre.org/techniques/T1621/
- T1059.001 PowerShell: https://attack.mitre.org/techniques/T1059/001/
- T1218 Signed Binary Proxy Execution: https://attack.mitre.org/techniques/T1218/
- T1197 BITS Jobs: https://attack.mitre.org/techniques/T1197/
- T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/

ATT&CK mappings in TriageBloom describe the behaviour represented by a rule. They do not prove attribution, intent, or compromise.

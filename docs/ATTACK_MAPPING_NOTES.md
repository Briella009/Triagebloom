# ATT&CK mapping notes

TriageBloom mappings describe the ATT&CK techniques represented by each rule. They provide analyst context; they are not claims that every tactic applies to every observed event.

The project follows the current MITRE ATT&CK Enterprise technique pages. T1078 (Valid Accounts) is associated with Initial Access, Persistence, Privilege Escalation, and Stealth. T1059.001 (PowerShell) is associated with Execution.

For a correlated T1078 + T1059.001 finding, TriageBloom shows the union of those tactic labels rather than adding Credential Access merely because failed authentication preceded the successful sign-in.

Risk and confidence values are deterministic triage scores used for prioritisation. They are not calibrated probabilities of compromise.

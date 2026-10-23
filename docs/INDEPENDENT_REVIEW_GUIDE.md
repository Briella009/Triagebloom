# Independent technical review guide

Use this guide to obtain genuine external feedback on TriageBloom. The review must not be written or scored by the maintainer on the reviewer's behalf.

## Reviewer profile

Use at least two independent cybersecurity professionals for the first review round. The project roadmap retains a stronger target of at least three practitioners before 1.0.

Suitable reviewers include:

- SOC analysts;
- detection engineers;
- incident responders;
- DFIR practitioners;
- security engineers;
- cybersecurity educators with hands-on detection experience.

Prefer reviewers who are not close relatives, direct reports, current co-authors on the TriageBloom study, or people whose endorsement is financially dependent on the maintainer.

## Safety and privacy

Use only:

- bundled synthetic fixtures;
- independently prepared synthetic data;
- public data whose licence permits the intended use;
- explicitly authorised sanitised data.

Do not send reviewers employer/client logs, credentials, tokens, patient data, customer data, or other confidential telemetry.

## Version record

Before testing, record:

- date;
- reviewer name and role;
- TriageBloom version;
- exact commit SHA;
- operating system;
- Python version;
- whether testing used CLI, local Streamlit, or the public demo.

## Review tasks

1. Read the README and install or open the application without live maintainer assistance where possible.
2. Run the bundled combined-incident scenario.
3. Inspect at least one authentication finding and one process/correlation finding.
4. Check whether the evidence IDs and trigger explanation support the conclusion.
5. Review the ATT&CK mapping and investigation guidance.
6. Run at least one benign synthetic case and one malicious synthetic case.
7. Download a pseudonymised report and check whether obvious identifiers are removed.
8. If technically appropriate, inspect the relevant source/test files.
9. Compare the workflow with tools the reviewer already knows, such as Sigma-based hunting tools, SIEM workflows, Hayabusa, Chainsaw, or Timesketch.
10. Record defects, ambiguous claims, false positives/negatives, and missing context.

## Questions the reviewer should answer

- Was installation/use reproducible?
- Were any findings technically incorrect?
- Were any expected findings missed?
- Was a benign case incorrectly escalated?
- Could the reviewer trace a finding back to evidence?
- Was the investigation guidance useful and safe?
- Was any ATT&CK mapping misleading?
- Did pseudonymisation behave as expected?
- What use case, if any, is TriageBloom better suited to than the reviewer's normal workflow?
- What is the most important limitation?
- What should be changed before 1.0?
- Does the reviewer see a genuinely distinctive contribution? If yes, what specifically?

## Evidence integrity

Keep the original feedback privately and preserve:

- the completed form;
- email/message showing who supplied it;
- testing date;
- commit/version;
- screenshots where permitted;
- consent for any public quotation.

Do not edit negative feedback out of the raw record. If a public summary is created, report the number invited, number completed, and material negative findings.

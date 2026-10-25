# 60-second demo video script

Use this outline for a short README/social demo. Record only synthetic data.

## 0-8 seconds — problem

Show the TriageBloom landing page.

Narration:

> "Raw security exports are hard to triage quickly when you do not have a full SIEM workflow. TriageBloom turns exported events into explainable findings."

## 8-25 seconds — run the demo

Open the live Streamlit app, leave the profile on `balanced`, choose **Demo data → Combined incident chain**, and click **Run analysis**.

Narration:

> "With the bundled synthetic incident chain, TriageBloom detects repeated authentication failures, a successful sign-in, suspicious PowerShell, and correlates them into one investigation path."

## 25-42 seconds — show explainability

Expand `TB-CORR-001`.

Show:

- evidence IDs;
- affected entities;
- MITRE ATT&CK context;
- triage score / rule confidence wording;
- investigation guidance.

Narration:

> "Every finding is traceable to the events that triggered it, with ATT&CK context and investigation guidance. The scores are deterministic triage heuristics, not probabilities of compromise."

## 42-52 seconds — privacy

Show the pseudonymised report option.

Narration:

> "Shareable reports can pseudonymise identifiers. Sensitive employer or client data should be processed locally, not uploaded to the public demo."

## 52-60 seconds — call to action

Show the GitHub repository.

Narration:

> "TriageBloom is open source. Try the demo, star it if it is useful, fork it to experiment, or contribute a focused pull request."

## Recording notes

- Keep the clip under 60 seconds.
- Do not show real security logs.
- Do not claim real-world accuracy from the synthetic evaluation.
- Link the repository and live demo in the post description.

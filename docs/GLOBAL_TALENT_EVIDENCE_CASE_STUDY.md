# TriageBloom: factual UK Global Talent evidence case study

**Status:** working evidence draft, not a claim of eligibility  
**Last reviewed:** 2026-10-23

## Important criterion caution

Current UK digital-technology rules for **Exceptional Promise** require recognition as a potential leader and evidence for at least two additional criteria. The innovation criterion is framed around innovation as a founder of a product-led digital technology company or as an employee working in a new digital field or concept.

A personal open-source repository does **not automatically satisfy that innovation criterion**.

Current official guidance also lists starting or contributing to open-source projects **where peers have acknowledged that the work advanced the field** as a possible type of evidence.

Official sources:

- https://www.gov.uk/global-talent-digital-technology/eligibility
- https://www.gov.uk/global-talent-digital-technology/documents-you-need-to-apply-endorsement
- https://www.gov.uk/guidance/immigration-rules/immigration-rules-appendix-global-talent

For TriageBloom, the safer current positioning is as potential evidence of **work beyond normal occupation / contribution to the digital-technology field**, and potentially as supporting material for a research criterion if the research is genuinely published or independently endorsed. Do not force the project into the innovation criterion unless the factual company/employment requirements and independent evidence genuinely fit.

## Problem addressed

Security analysts, learners, educators, and small teams may need to review exported security events without access to a full production SIEM/EDR tenant. Raw exports can be difficult to interpret, while sharing investigation artefacts can expose identifiers.

TriageBloom addresses this narrow workflow by normalising exported security-event data, applying inspectable deterministic rules, correlating selected cross-source sequences, and generating evidence-linked reports.

## Verified technical contribution

Public repository:

https://github.com/Briella009/Triagebloom

Live demo:

https://triagebloom.streamlit.app

The public repository currently demonstrates:

- local CSV/JSON/JSONL/NDJSON ingestion;
- Microsoft Entra and Defender context preservation;
- deterministic authentication and process detections;
- authentication-to-endpoint correlation;
- ATT&CK context;
- evidence IDs and investigation guidance;
- configurable profiles, allow-lists, and suppressions;
- pseudonymised HTML/JSON reports;
- local CLI and Streamlit interface;
- automated CI and regression tests;
- synthetic labelled evaluation;
- pre-results external research/evaluation infrastructure.

## Personal contribution evidence

The repository history should be used to show the maintainer's role over time through:

- initial public release;
- subsequent compatibility fixes;
- CI setup;
- Microsoft/security-context expansion;
- Streamlit interface;
- ATT&CK/score corrections;
- research-evaluation pull requests;
- documentation and test evolution.

Do not claim that every line was manually written without assistance if that is not true. Describe the role accurately as creator/maintainer, technical decision-maker, tester, researcher, and integrator, and be prepared to explain any AI-assisted or third-party tooling used during development.

## Measurable results currently safe to state

Safe statements must be tied to a commit/run.

Examples already supported by repository history include:

- CI execution across supported Python versions;
- a Streamlit smoke test;
- synthetic rule-level verification;
- test/coverage results recorded for specific historical releases;
- existence of reproducible external-dataset and performance protocols.

Do not present synthetic precision/recall/F1 as production SOC accuracy.

## Evidence still required

### Independent acknowledgement

Required before treating the repository as strong open-source advancement evidence:

- at least two genuine independent technical reviews for the first round;
- preferably the roadmap target of three practitioners before 1.0;
- permissioned quotations only;
- reviewer identity/credentials retained privately;
- version/commit tied to each review.

### External use or adoption

Record only if real:

- independent users;
- genuine GitHub issues or pull requests;
- forks/contributions with evidence of use;
- workshop or teaching use by third parties;
- organisational pilot/adoption;
- citations or references in publications, talks, course material, or technical writing.

Do not count the maintainer's own star, downloads, or self-generated screenshots as independent impact.

### Controlled pilot

Complete the documented analyst pilot and preserve:

- number invited/completed;
- participant experience level;
- raw-log versus TriageBloom condition;
- time to first correct finding;
- total investigation time;
- correct/missed findings;
- false-positive acceptance;
- clarity/usefulness scores;
- negative feedback.

### External dataset results

Run only the frozen, documented protocols. Preserve:

- dataset source/version;
- hashes;
- selected member;
- exact commit;
- configuration;
- commands;
- inclusion/exclusion rules;
- negative results;
- machine specification for performance claims.

## Current Global Talent conclusion

TriageBloom is credible technical evidence of sustained open-source cybersecurity work and is increasingly independently evaluable.

It is **not yet sufficient by itself to establish the innovation criterion**. The strongest missing factor is external acknowledgement and impact. If independent practitioners validate the contribution, external results are published responsibly, and genuine third-party use emerges, the project can become a materially stronger evidence item.

The final application should still rely on the applicant's broader evidence portfolio rather than making TriageBloom carry the application alone.

# TriageBloom novelty review

**Review date:** 2026-10-23

This document compares TriageBloom with established open-source security-analysis tools. It is a positioning review, not proof that TriageBloom is legally or academically novel.

## Reference tools

### Hayabusa

Hayabusa is a fast Windows event-log forensics and threat-hunting tool written in Rust. It supports Sigma detection rules, including Sigma v2 correlation, and produces consolidated CSV/JSON/JSONL timelines.

Sources:

- https://github.com/Yamato-Security/hayabusa
- https://yamato-security.github.io/hayabusa/

### Chainsaw

Chainsaw is a rapid first-response tool for Windows forensic artefacts. It supports Sigma and custom Chainsaw rules, searches event logs, and analyses artefacts including MFT, Shimcache/Amcache, SRUM, registry hives, and other Windows forensic sources.

Source:

- https://github.com/WithSecureOpenSource/chainsaw

### Timesketch

Timesketch is an open-source collaborative forensic-timeline analysis platform. It focuses on organizing, searching, annotating, and collaboratively analysing timeline data.

Source:

- https://github.com/google/timesketch

## What is standard rather than novel

The following TriageBloom characteristics are useful but should not be claimed as original by themselves:

- rule-based detection;
- ATT&CK mappings;
- local/offline security-event analysis;
- CSV/JSON output;
- suspicious PowerShell detection;
- LOLBin detection;
- authentication-pattern detection;
- correlation of multiple events;
- forensic timelines or event normalization in general;
- browser interfaces for security analysis;
- synthetic regression tests.

Hayabusa already supports large-scale Windows-event hunting and Sigma correlation. Chainsaw already provides lightweight Windows artefact hunting with Sigma/custom rules. Timesketch already provides rich forensic timeline analysis and collaboration.

## Potentially distinctive combination

TriageBloom's most defensible differentiation is the **combination and target workflow**, not a claim that any single primitive is unprecedented.

Potentially distinctive elements include:

1. a dependency-light local core aimed at exported-event triage rather than a full SIEM;
2. a vendor-neutral canonical model with dedicated Microsoft Entra and Defender context;
3. explicit cross-domain correlation from authentication failures to a successful sign-in and then suspicious endpoint execution;
4. evidence-linked findings that expose rule IDs, event IDs, entities, trigger reasoning, ATT&CK context, and investigation guidance;
5. pseudonymised shareable reports built into the same workflow;
6. a public demo separated from the local privacy boundary;
7. unusually explicit reproducibility and claim-boundary documentation for an early-stage open-source SOC tool;
8. a research track that refuses to generate measured figures when required external metrics are absent.

These points can support a credible design contribution, but they do **not** yet prove market or field innovation.

## What is not substantiated

Do not currently claim:

- that TriageBloom is the first local-first SOC triage tool;
- that deterministic correlation is novel;
- that its detection rules outperform Sigma, Hayabusa, Chainsaw, Sentinel, Defender, or another platform;
- that it reduces analyst investigation time;
- that it has a lower real-world false-positive rate;
- that it is more resource-efficient than competing tools;
- that it has material industry adoption;
- that its triage/confidence scores are calibrated probabilities;
- that the project has advanced the field merely because the repository exists.

## What would strengthen an innovation claim

The strongest next evidence would be independent and comparative:

- practitioners identifying a concrete workflow gap that TriageBloom solves better for their use case;
- external-dataset results under frozen rules and documented scope;
- controlled analyst-study evidence showing a measurable workflow benefit;
- third-party issues, pull requests, forks, citations, workshop use, or organizational adoption;
- a publication or expert review that identifies the contribution as distinct from existing tools;
- a reproducible comparison against an appropriate baseline, with negative results retained.

## Current novelty conclusion

TriageBloom has a coherent and potentially distinctive **product/workflow design**, particularly around explainable local triage, Microsoft-context preservation, privacy-aware reporting, and narrow cross-source correlation.

That is not the same as proving the UK Global Talent innovation criterion. At present, the project should be described as an independently evaluable open-source cybersecurity contribution whose innovation case is **promising but not yet independently substantiated**.

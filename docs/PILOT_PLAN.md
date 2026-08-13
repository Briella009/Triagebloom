# Pilot plan

This plan is designed to test usefulness rather than collect vanity metrics.

## Pilot question

Can a learner or small-team analyst use TriageBloom to identify and explain suspicious patterns in an exported event set faster and more consistently than reviewing the rows manually?

## Participants

Start with 10 to 20 consenting participants across two groups:

- early-career SOC learners
- practising analysts or mentors

Do not use confidential employer data. Provide synthetic cases with known ground truth.

## Tasks

Each participant completes two equivalent cases:

1. manual review of a CSV or JSON export
2. review using TriageBloom

Alternate the order between participants to reduce learning-order bias.

## Measures

Collect:

- time to first correct finding
- total analysis time
- true findings identified
- false positives accepted as malicious
- confidence before and after using the tool
- usefulness score from 1 to 5
- clarity score from 1 to 5
- one improvement suggestion

## Success criteria for the next release

The 0.2 pilot target is:

- at least 10 completed sessions
- at least 80 percent of participants able to run the tool without live help
- median clarity score of at least 4 out of 5
- no critical privacy or execution defect
- at least three concrete improvements incorporated into a tagged release

These are project targets, not visa thresholds or official endorsement requirements.

## Evidence integrity

- Obtain written consent for testimonials and screenshots.
- Report the number of invited and completed participants.
- Keep raw feedback privately.
- Publish aggregated results and methodology.
- Do not remove negative responses from the analysis.
- Do not describe trainees as organisational adopters unless an organisation genuinely approved or used the tool.

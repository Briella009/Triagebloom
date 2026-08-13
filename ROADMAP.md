# Roadmap

The roadmap uses measurable release criteria so progress can be independently verified.

## 0.1 - Working MVP

- [x] Parse CSV and JSON exports
- [x] Normalise common security fields
- [x] Detect password spray and brute force
- [x] Detect success after repeated failures
- [x] Detect suspicious PowerShell and common LOLBins
- [x] Generate explainable HTML and JSON reports
- [x] Add automated tests and synthetic data

## 0.2 - Microsoft security context

- [ ] Add dedicated Microsoft Entra ID schema adapter
- [ ] Add Microsoft Defender process and alert adapters
- [ ] Include conditional-access and authentication-method context
- [ ] Add MFA fatigue detection
- [ ] Publish at least three sanitised schema fixtures
- [ ] Reach at least 80 percent test coverage

## 0.3 - Evaluation and incident correlation

- [ ] Correlate authentication and endpoint events into incident chains
- [ ] Add configurable rule profiles for learners and small SOC teams
- [ ] Publish a labelled synthetic evaluation dataset
- [ ] Report precision, recall, and false-positive rate on the labelled dataset
- [ ] Add rule-suppression and allow-list configuration

## 0.4 - Community and integrations

- [ ] Import a safe subset of Sigma rules
- [ ] Add a browser interface that runs locally
- [ ] Add a documented plugin interface for parsers and detections
- [ ] Publish a contributor guide for new detection rules
- [ ] Complete an external pilot with documented, consented feedback

## 1.0 - Stable educational and small-team release

- [ ] Stable input schema and compatibility policy
- [ ] Reproducible benchmark results
- [ ] Security review and threat model
- [ ] Signed releases and software bill of materials
- [ ] At least two independent maintainers or regular external contributors

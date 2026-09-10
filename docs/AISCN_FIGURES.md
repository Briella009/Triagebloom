# AISCN 2027 figure generation

The unpublished manuscript is kept outside the public repository, but the figure-generation method is public so measured plots can be reproduced from accepted result JSON.

## Static system figures

Generate the architecture and correlation-sequence figures with:

```bash
python scripts/research_figures.py \
  --output-dir evaluation/external/figures
```

This creates:

- `figure1-architecture.svg`
- `figure2-correlation-sequence.svg`

These figures describe implemented system structure only. They contain no external-dataset result claims.

## Measured profile comparison

After the frozen COMISET laboratory matrix has been accepted as final:

```bash
python scripts/research_figures.py \
  --output-dir evaluation/external/figures \
  --comiset-matrix evaluation/external/comiset-lab-profile-matrix.json
```

This additionally creates `figure3-profile-comparison.svg` from the recorded binary supported-scope precision, recall and F1 values for learner, balanced and strict.

The script refuses to produce the measured profile figure when those metrics are absent. Do not substitute synthetic regression results.

## Measured throughput figure

After the frozen performance benchmark has been accepted as final:

```bash
python scripts/research_figures.py \
  --output-dir evaluation/external/figures \
  --performance evaluation/external/performance-balanced.json
```

This additionally creates `figure4-throughput-scaling.svg` from median detection throughput values. At least two measured event sizes are required.

## Complete figure command

```bash
python scripts/research_figures.py \
  --output-dir evaluation/external/figures \
  --comiset-matrix evaluation/external/comiset-lab-profile-matrix.json \
  --performance evaluation/external/performance-balanced.json
```

## Claim boundaries

- Static diagrams describe software behaviour; they are not performance evidence.
- The profile plot must come from the frozen external COMISET matrix, not the eight synthetic regression cases.
- The throughput plot must come from the isolated performance benchmark and must be accompanied in the paper by the machine, Python version, exact commit, event counts and run procedure.
- Do not visually truncate axes in a way that exaggerates small profile differences.
- Keep the SVG source output so figures remain inspectable and publication-ready at arbitrary resolution.

The `evaluation/external/` directory is gitignored, so private/unpublished measured outputs remain local unless deliberately published later under compatible dataset and conference policies.

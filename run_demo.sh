#!/usr/bin/env sh
set -eu
python -m triagebloom analyze sample_data/combined_incident.json --output-dir reports --disable-off-hours --redact

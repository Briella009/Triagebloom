#!/usr/bin/env sh
set -eu
python -m triagebloom analyze sample_data/demo_events.json --output-dir reports

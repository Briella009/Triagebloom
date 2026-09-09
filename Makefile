.PHONY: test coverage evaluate demo benchmark clean

test:
	python -m unittest discover -s tests -v

coverage:
	coverage run --source=src/triagebloom -m unittest discover -s tests -v
	coverage report --fail-under=80

evaluate:
	python scripts/evaluate_labelled.py

demo:
	python -m triagebloom analyze sample_data/combined_incident.json --output-dir reports --disable-off-hours

benchmark:
	python scripts/benchmark.py --events 10000 --repeat 3

clean:
	rm -f reports/*.html reports/*.json
	rm -f evaluation/results-v0.2.0.json

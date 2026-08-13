.PHONY: test demo benchmark clean

test:
	python -m unittest discover -s tests -v

demo:
	python -m triagebloom analyze sample_data/demo_events.json --output-dir reports

benchmark:
	python scripts/benchmark.py --events 10000 --repeat 3

clean:
	rm -f reports/*.html reports/*.json

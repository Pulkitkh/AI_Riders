.PHONY: demo selftest replay dash test eval sweep train bench clean

demo: selftest test replay eval sweep   ## everything a judge needs to see

selftest:
	@python3 -m prahari.cli selftest

replay:
	@python3 -m prahari.cli replay

dash:
	@python3 -m prahari.api --port 8000

test:
	@python3 tests/test_prahari.py

eval:
	@python3 eval/evaluate.py

sweep:
	@python3 eval/jitter_sweep.py

train:
	@python3 scripts/train.py

bench:
	@python3 -m prahari.cli bench

clean:
	@rm -rf data/alerts.jsonl **/__pycache__ prahari/__pycache__ prahari/detectors/__pycache__

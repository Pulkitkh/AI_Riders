.PHONY: demo selftest replay live pcap dash test eval sweep train bench clean

demo:   ## everything a judge needs to see (Windows: python scripts/demo.py)
	@python3 scripts/demo.py

selftest:
	@python3 -m prahari.cli selftest

replay:
	@python3 -m prahari.cli replay

pcap:   ## write a genuine wire-format capture to data/demo.pcap
	@python3 scripts/make_pcap.py --out data/demo.pcap --duration 1800

live: pcap   ## run the pipeline on real packet bytes
	@python3 -m prahari.cli live --pcap data/demo.pcap

dash:
	@python3 -m web.server --port 8000

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
	@rm -rf data/alerts.jsonl data/demo.pcap **/__pycache__ prahari/__pycache__ prahari/detectors/__pycache__

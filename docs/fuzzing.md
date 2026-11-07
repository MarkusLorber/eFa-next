# Fuzzing the parsers

eFa reads data from outside — mail, Office and PDF attachments, DMARC and TLS reports, bounces — with its own parsers. A
fuzzer feeds them malformed input to make sure a bad file is refused cleanly, never crashes and never lets something through.

- `scripts/fuzz.py`, standard library only, a fixed seed so a failure can be reproduced, and limits on size, depth and time.
- Covers the content disarm (OOXML, OLE, PDF, links), MIME handling, the DMARC XML, DLP and disclaimers.
- No external entities (no XXE); archives are read with a bound on members, size and nesting.
- Runs in CI for a set time (`scripts/ci.sh`). A crash or an attachment that slips through fails the build.

Run it by hand with `python3 scripts/fuzz.py --seconds 60`; add `--seed N` to repeat a run.

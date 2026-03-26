---
name: verify
description: Build the project and run all tests to verify changes are correct
---

Run the following commands in sequence, stopping on first failure:

1. `make build` — compile in release mode
2. `swift test` — run all tests

Report the results. If tests fail, analyze the failure output and suggest fixes.

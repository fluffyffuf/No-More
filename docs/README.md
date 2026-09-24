# NOMORE Documentation

This repository contains the initial architecture and CLI scaffold for a responsible web security assessment platform.

## Contents

- CLI usage examples
- configuration layout
- scope management model
- plugin architecture
- reporting contract
- local safety-oriented test fixtures

## Running the CLI

```bash
python -m nomore --help
python -m nomore scan example.com --profile standard
python -m nomore scope add "*.example.com"
python -m nomore report --format json --output report.json
```

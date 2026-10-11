# CyberGuard — Security Log Analyzer

CyberGuard is a Python command-line tool that analyzes authentication logs,
counts login events, detects repeated failed login attempts, and exports
findings to CSV.

The included log file contains synthetic training data.

## Features

- Count failed and successful login events.
- Detect repeated failed login attempts by IP address.
- Configure the detection threshold.
- Validate IP addresses before counting them.
- Export flagged addresses to CSV.
- Run automated tests using Python's unittest framework.

## Requirements

- Python 3.10 or newer
- Git

No third-party Python packages are required.

## Setup

Create and activate a virtual environment on Ubuntu:

    python3 -m venv .venv
    source .venv/bin/activate

## Usage

Analyze the sample log:

    python3 main.py

Use a threshold of five failed attempts:

    python3 main.py --threshold 5

Specify the input file and report location:

    python3 main.py --log sample_logs/auth.log --threshold 4 --output reports/suspicious_ips.csv

## Tests

Run the automated tests:

    python3 -m unittest discover -s tests -v

## Example Results

The included sample contains 12 events:
- 10 failed login attempts
- 2 successful login attempts
- 0 unrecognized events

With the default threshold of four, CyberGuard flags:
- 10.0.0.8 — 5 failed attempts
- 192.168.1.20 — 4 failed attempts

The CSV report contains the IP address, failed-attempt count, and status.

## Limitations

Repeated failed logins can indicate suspicious activity but do not prove
an attack occurred. This version counts attempts across the entire log file
rather than within a time window.

CyberGuard is an educational project, not a replacement for a production
security monitoring platform. Only analyze logs you are authorized to access.

## Future Improvements

- Time-window-based detection
- Support for standard Linux authentication logs
- JSON report generation
- Automated testing with GitHub Actions

## License

Licensed under the MIT License. See LICENSE.

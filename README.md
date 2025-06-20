# Scanner

## Requirements
- Python 3.10+

## Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy `settings.example.yaml` to `settings.yaml` and adjust the values to your environment.
3. Define the list of user agents in `settings.yaml` under `user_agents.agents`.

### scan_ranges examples
- CIDR notation:
  ```yaml
  range:
    scan_ranges:
      - 2.16.37.0/24
  ```
- Start/End pair:
  ```yaml
  range:
    scan_ranges:
      - "2.16.37.0 2.16.37.255"
  ```
- Multiple ranges:
  ```yaml
  range:
    scan_ranges:
      - 2.16.37.0/24
      - "2.16.37.0 2.16.37.255"
  ```

## Usage
Run the scanner:
```bash
python main.py
```

Results will be saved in the `results/` directory as CSV and JSON files.
Output filenames now include the full scan range so each run writes to
distinct files.

### Captured headers

The scanner now stores selected response headers from each HTTP/HTTPS request.
Currently the following headers are saved:

- `Server`
- `Content-Type`

The JSON output adds a `headers` object for both the `http` and `https`
sections. Example:

```json
{
  "ip": "192.0.2.1",
  "http": {
    "port": 80,
    "code": 200,
    "latency_ms": 48,
    "headers": {
      "Server": "nginx/1.22.0",
      "Content-Type": "text/html; charset=utf-8"
    }
  },
  "https": {
    "port": 443,
    "code": 404,
    "latency_ms": 76,
    "headers": {
      "Server": "Apache",
      "Content-Type": "text/html"
    }
  }
}
```

If a request fails, optional `error` or `error_message` fields may appear in the
corresponding protocol section.

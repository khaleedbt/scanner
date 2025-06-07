# Scanner

## Requirements
- Python 3.10+

## Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy `settings.example.yaml` to `settings.yaml` and adjust the values to your environment.

### scan_range examples
- CIDR notation:
  ```yaml
  range:
    scan_range: 2.16.37.0/24
  ```
- Start/End pair:
  ```yaml
  range:
    scan_range: "2.16.37.0 2.16.37.255"
  ```

## Usage
Run the scanner:
```bash
python main.py
```

Results will be saved in the `results/` directory as CSV and JSON files.

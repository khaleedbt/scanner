import requests
import time
import random
import yaml
import json
import csv
import os
from ipaddress import ip_network, ip_address
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.68.0"
]

def load_settings():
    """Load configuration and override defaults if applicable."""
    config_path = "settings.yaml"
    if not os.path.exists(config_path):
        example_path = "settings.example.yaml"
        if os.path.exists(example_path):
            print(
                f"[!] {config_path} not found, using {example_path}. "
                "Create settings.yaml to override defaults."
            )
            config_path = example_path
        else:
            raise FileNotFoundError(
                f"{config_path} not found. Please create it or copy from {example_path}."
            )

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    # Allow overriding USER_AGENTS from the settings file
    agents = config.get("user_agents", {}).get("agents")
    if isinstance(agents, list) and agents:
        global USER_AGENTS
        USER_AGENTS = agents

    return config

def check_url(url, headers):
    try:
        start = time.time()
        r = requests.get(url, headers=headers, timeout=3, verify=False)
        elapsed = int((time.time() - start) * 1000)  # ms
        if r.status_code < 500:
            return r.status_code, elapsed, r.headers
    except requests.RequestException:
        pass
    return None, None, {}

def parse_scan_range(range_str):
    """Return an iterable of IP addresses from a CIDR or start-end string."""
    range_str = range_str.strip()
    if "/" in range_str:
        network = ip_network(range_str, strict=False)
        return network.hosts()
    parts = range_str.split()
    if len(parts) != 2:
        raise ValueError(
            "scan_range must be CIDR or two space-separated IPs"
        )
    start_ip = ip_address(parts[0])
    end_ip = ip_address(parts[1])
    if int(start_ip) > int(end_ip):
        start_ip, end_ip = end_ip, start_ip
    return (ip_address(ip) for ip in range(int(start_ip), int(end_ip) + 1))

def scan_ip(ip, agents=None):
    """Return headers and open ports for a single IP."""
    if agents is None:
        agents = USER_AGENTS

    headers = {"User-Agent": random.choice(agents)}

    http_headers = {}
    https_headers = {}
    ports = []

    url_http = f"http://{ip}"
    code, latency, resp_headers = check_url(url_http, headers)
    if code:
        print(f"[+] HTTP ответ от {ip}: {code} ({latency}ms)")
        ports.append(80)
        http_headers = resp_headers

    url_https = f"https://{ip}"
    code, latency, resp_headers = check_url(url_https, headers)
    if code:
        print(f"[+] HTTPS ответ от {ip}: {code} ({latency}ms)")
        ports.append(443)
        https_headers = resp_headers

    if ports:
        server_header = https_headers.get("Server") or http_headers.get("Server")
        powered_by_header = (
            https_headers.get("X-Powered-By")
            or http_headers.get("X-Powered-By")
        )
        return {
            "ip": ip,
            "ports": ports,
            "server": server_header,
            "powered_by": powered_by_header,
        }
    return None

def main():
    config = load_settings()
    scan_range = config["range"]["scan_range"]
    country = config["range"].get("country_code", "XX").upper()

    # Iterate over either CIDR or explicit start/end IPs
    ip_iter = parse_scan_range(scan_range)

    # Base name uses the starting IP of the range
    ip_base = scan_range.split()[0].split("/")[0].replace(".", "_")
    filename_id = f"{ip_base}_{country}"
    output_dir = "results"
    os.makedirs(output_dir, exist_ok=True)
    csv_file = os.path.join(output_dir, f"{filename_id}.csv")
    json_file = os.path.join(output_dir, f"{filename_id}.json")

    # Создание файлов для результатов

    with open(csv_file, "w", newline="") as f_csv, open(json_file, "w") as f_json:
        csv_writer = csv.DictWriter(
            f_csv,
            fieldnames=["ip", "ports", "server", "powered_by"],
        )
        csv_writer.writeheader()

        f_json.write("[\n")  # JSON-массив открывается
        first = True

        try:
            for ip in ip_iter:
                print(f"[ ] Проверка IP: {ip}")
                entry = scan_ip(str(ip), USER_AGENTS)

                if entry:
                    csv_writer.writerow(entry)

                    if not first:
                        f_json.write(",\n")
                    f_json.write(json.dumps(entry, indent=2))
                    first = False

                time.sleep(1)
        except KeyboardInterrupt:
            print("Сканирование прервано пользователем")
        finally:
            f_json.write("\n]\n")  # Закрываем JSON-массив

    print(f"[✓] CSV сохранён в {csv_file}")
    print(f"[✓] JSON сохранён в {json_file}")

if __name__ == "__main__":
    main()

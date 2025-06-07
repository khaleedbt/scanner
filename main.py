import requests
import time
import random
import yaml
import json
import csv
import os
from ipaddress import ip_network
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
    with open("settings.yaml", "r") as f:
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
            return r.status_code, elapsed
    except requests.RequestException:
        pass
    return None, None

def scan_ip(ip, agents=None):
    """Return combined HTTP/HTTPS results for a single IP."""
    if agents is None:
        agents = USER_AGENTS

    headers = {"User-Agent": random.choice(agents)}
    http_info = None
    https_info = None

    url_http = f"http://{ip}"
    code, latency = check_url(url_http, headers)
    if code:
        print(f"[+] HTTP ответ от {ip}: {code} ({latency}ms)")
        http_info = {
            "port": 80,
            "code": code,
            "latency_ms": latency,
        }

    url_https = f"https://{ip}"
    code, latency = check_url(url_https, headers)
    if code:
        print(f"[+] HTTPS ответ от {ip}: {code} ({latency}ms)")
        https_info = {
            "port": 443,
            "code": code,
            "latency_ms": latency,
        }

    if http_info or https_info:
        return {
            "ip": ip,
            "http": http_info,
            "https": https_info,
        }
    return None

def main():
    config = load_settings()
    cidr = config["range"]["scan_range"]
    country = config["range"].get("country_code", "XX").upper()

    # Allow CIDR ranges that are not aligned to network boundaries
    network = ip_network(cidr, strict=False)

    ip_base = cidr.split("/")[0].replace(".", "_")
    filename_id = f"{ip_base}_{country}"
    output_dir = "results"
    os.makedirs(output_dir, exist_ok=True)
    csv_file = os.path.join(output_dir, f"{filename_id}.csv")
    json_file = os.path.join(output_dir, f"{filename_id}.json")

    # Создание файлов для результатов

    with open(csv_file, "w", newline="") as f_csv, open(json_file, "w") as f_json:
        csv_writer = csv.DictWriter(
            f_csv,
            fieldnames=[
                "ip",
                "http_code",
                "http_latency_ms",
                "https_code",
                "https_latency_ms",
            ],
        )
        csv_writer.writeheader()

        f_json.write("[\n")  # JSON-массив открывается
        first = True

        try:
            for ip in network.hosts():
                print(f"[ ] Проверка IP: {ip}")
                entry = scan_ip(str(ip), USER_AGENTS)

                if entry:
                    csv_writer.writerow({
                        "ip": entry["ip"],
                        "http_code": entry.get("http", {}).get("code", ""),
                        "http_latency_ms": entry.get("http", {}).get("latency_ms", ""),
                        "https_code": entry.get("https", {}).get("code", ""),
                        "https_latency_ms": entry.get("https", {}).get("latency_ms", ""),
                    })

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

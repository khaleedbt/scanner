import requests
import time
import random
import yaml
import uuid
import json
import csv
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
    with open("settings.yaml", "r") as f:
        return yaml.safe_load(f)

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

def scan_ip(ip):
    results = []
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    url_http = f"http://{ip}"
    code, latency = check_url(url_http, headers)
    if code:
        print(f"[+] HTTP ответ от {ip}: {code} ({latency}ms)")
        results.append({
            "ip": ip,
            "port": 80,
            "protocol": "http",
            "code": code,
            "latency_ms": latency
        })

    url_https = f"https://{ip}"
    code, latency = check_url(url_https, headers)
    if code:
        print(f"[+] HTTPS ответ от {ip}: {code} ({latency}ms)")
        results.append({
            "ip": ip,
            "port": 443,
            "protocol": "https",
            "code": code,
            "latency_ms": latency
        })

    return results

def main():
    config = load_settings()
    cidr = config["range"]["scan_range"]
    country = config["range"]["country"]

    network = ip_network(cidr)

    filename_id = uuid.uuid4().hex[:8]
    csv_file = f"{filename_id}.csv"
    json_file = f"{filename_id}.json"

    # Подготовка файлов
    json_log = []

    with open(csv_file, "w", newline="") as f_csv, open(json_file, "w") as f_json:
        csv_writer = csv.DictWriter(f_csv, fieldnames=["ip", "port", "protocol", "code", "latency_ms"])
        csv_writer.writeheader()

        f_json.write("[\n")  # JSON-массив открывается
        first = True

        for ip in network.hosts():
            print(f"[ ] Проверка IP: {ip}")
            results = scan_ip(str(ip))

            for entry in results:
                # CSV — запись строки
                csv_writer.writerow(entry)

                # JSON — построчная запись объектов
                if not first:
                    f_json.write(",\n")
                f_json.write(json.dumps(entry, indent=2))
                first = False

            time.sleep(1)

        f_json.write("\n]\n")  # Закрываем JSON-массив

    print(f"[✓] CSV сохранён в {csv_file}")
    print(f"[✓] JSON сохранён в {json_file}")

if __name__ == "__main__":
    main()
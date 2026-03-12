import os
import re
from pathlib import Path
from collections import Counter

import requests
import pandas as pd
import matplotlib.pyplot as plt
from dotenv import load_dotenv

load_dotenv()


INPUT_FILE = "2024-11-26-traffic-analysis-exercise-alerts.txt"
REPORT_CSV = "report.csv"
REPORT_JSON = "report.json"
GRAPH_PNG = "top_alerted_ips.png"

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "").strip()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

VT_MALICIOUS_THRESHOLD = 1
VT_SUSPICIOUS_THRESHOLD = 1


def parse_alerts_txt(file_path: str) -> pd.DataFrame:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Файл не найден: {file_path}")

    raw_text = path.read_text(encoding="utf-8", errors="ignore")
    blocks = [block.strip() for block in re.split(r"-{20,}", raw_text) if block.strip()]
    rows = []

    for block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if len(lines) < 3:
            continue

        first_line = lines[0]
        second_line = lines[1]
        third_line = lines[2] if len(lines) > 2 else ""

        header_match = re.search(
            r"Count:(\d+)\s+Event#([^\s]+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\s+UTC)?)",
            first_line
        )
        count = int(header_match.group(1)) if header_match else 1
        event_id = header_match.group(2) if header_match else ""
        timestamp = header_match.group(3) if header_match else ""

        signature = second_line

        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)", third_line)
        src_ip = ip_match.group(1) if ip_match else ""
        dst_ip = ip_match.group(2) if ip_match else ""

        protocol = ""
        src_port = None
        dst_port = None

        for line in lines:
            proto_match = re.search(
                r"Protocol:\s*(\S+)\s+sport=(\d+)\s*->\s*dport=(\d+)",
                line
            )
            if proto_match:
                protocol = proto_match.group(1)
                src_port = int(proto_match.group(2))
                dst_port = int(proto_match.group(3))
                break

        severity = detect_severity(signature)

        rows.append({
            "count": count,
            "event_id": event_id,
            "timestamp": timestamp,
            "signature": signature,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "severity": severity,
        })

    return pd.DataFrame(rows)


def detect_severity(signature: str) -> str:
    text = signature.lower()
    if any(word in text for word in ["trojan", "rat", "malicious", "cnc", "c2"]):
        return "high"
    if any(word in text for word in ["exploit", "overflow", "dos", "unsafe", "hostile"]):
        return "medium"
    return "low"


def vt_check_ip(ip: str) -> dict:
    if not VT_API_KEY:
        return {
            "ip": ip,
            "vt_status": "skipped",
            "vt_malicious": None,
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "vt_last_analysis_date": None,
            "vt_error": "VT_API_KEY not set",
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "ip": ip,
            "vt_status": "ok",
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless": stats.get("harmless", 0),
            "vt_undetected": stats.get("undetected", 0),
            "vt_last_analysis_date": attrs.get("last_analysis_date"),
            "vt_error": "",
        }
    except requests.RequestException as e:
        return {
            "ip": ip,
            "vt_status": "error",
            "vt_malicious": None,
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "vt_last_analysis_date": None,
            "vt_error": str(e),
        }


def extract_possible_cves(signatures: list[str]) -> list[str]:
    cves = set()
    for sig in signatures:
        found = re.findall(r"CVE-\d{4}-\d{4,7}", sig, flags=re.IGNORECASE)
        for cve in found:
            cves.add(cve.upper())
    return sorted(cves)


def get_default_cves() -> list[str]:
    return [
        "CVE-2021-36942",
        "CVE-2017-0144",
        "CVE-2020-0796",
    ]


def vulners_get_cve_info(cve_id: str) -> dict:
    if not VULNERS_API_KEY:
        return {
            "cve": cve_id,
            "status": "skipped",
            "title": "VULNERS_API_KEY not set",
            "cvss": None,
            "description": "",
        }

    url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": VULNERS_API_KEY,
    }
    payload = {
        "query": cve_id,
        "skip": 0,
        "size": 1,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        search_items = data.get("data", {}).get("search", [])

        if not search_items:
            return {
                "cve": cve_id,
                "status": "not_found",
                "title": "",
                "cvss": None,
                "description": "",
            }

        item = search_items[0]
        cvss_obj = item.get("cvss", {}) or {}
        cvss = cvss_obj.get("score")

        return {
            "cve": cve_id,
            "status": "ok",
            "title": item.get("title", ""),
            "cvss": cvss,
            "description": (item.get("description") or "")[:500],
        }
    except requests.RequestException as e:
        return {
            "cve": cve_id,
            "status": "error",
            "title": str(e),
            "cvss": None,
            "description": "",
        }


def send_telegram_message(text: str) -> tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set"

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
    }

    try:
        response = requests.post(url, data=payload, timeout=30)
        response.raise_for_status()
        return True, "ok"
    except requests.RequestException as e:
        return False, str(e)


def build_ip_summary(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return pd.DataFrame(columns=["ip", "alerts_total", "high_count", "medium_count", "low_count"])

    rows = []
    for ip, group in alerts_df.groupby("dst_ip"):
        rows.append({
            "ip": ip,
            "alerts_total": int(group["count"].sum()),
            "high_count": int(group.loc[group["severity"] == "high", "count"].sum()),
            "medium_count": int(group.loc[group["severity"] == "medium", "count"].sum()),
            "low_count": int(group.loc[group["severity"] == "low", "count"].sum()),
        })

    return pd.DataFrame(rows).sort_values(["high_count", "alerts_total"], ascending=False)


def pick_ips_for_vt(alerts_df: pd.DataFrame) -> list[str]:
    ips = set(alerts_df["src_ip"].dropna().tolist()) | set(alerts_df["dst_ip"].dropna().tolist())
    return sorted(ip for ip in ips if ip and not is_private_ip(ip))


def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b, c, d = [int(x) for x in parts]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def decide_actions(report_df: pd.DataFrame) -> pd.DataFrame:
    actions = []

    for _, row in report_df.iterrows():
        action = "log_only"

        vt_mal = row.get("vt_malicious")
        vt_susp = row.get("vt_suspicious")
        severity = row.get("severity")

        if severity == "high":
            action = "alert_and_block_simulated"

        if pd.notna(vt_mal) and vt_mal is not None and vt_mal >= VT_MALICIOUS_THRESHOLD:
            action = "alert_and_block_simulated"

        if pd.notna(vt_susp) and vt_susp is not None and vt_susp >= VT_SUSPICIOUS_THRESHOLD and action == "log_only":
            action = "alert_only"

        actions.append(action)

    result = report_df.copy()
    result["action"] = actions
    return result


def save_chart(alerts_df: pd.DataFrame) -> None:
    if alerts_df.empty:
        return

    grouped = (
        alerts_df.groupby("dst_ip")["count"]
        .sum()
        .sort_values(ascending=False)
        .head(5)
    )

    if grouped.empty:
        return

    plt.figure(figsize=(10, 6))
    plt.bar(grouped.index, grouped.values)
    plt.title("Top IP по количеству событий")
    plt.xlabel("IP")
    plt.ylabel("Количество")
    plt.xticks(rotation=25)
    plt.tight_layout()
    plt.savefig(GRAPH_PNG)
    plt.close()


def main():
    alerts_df = parse_alerts_txt(INPUT_FILE) 
    if alerts_df.empty:
        return

    ips_for_vt = pick_ips_for_vt(alerts_df)
    vt_results = [vt_check_ip(ip) for ip in ips_for_vt]
    vt_df = pd.DataFrame(vt_results)

    cves_from_signatures = extract_possible_cves(alerts_df["signature"].tolist())
    if not cves_from_signatures:
        cves_from_signatures = get_default_cves()

    vulners_results = [vulners_get_cve_info(cve) for cve in cves_from_signatures]
    vulners_df = pd.DataFrame(vulners_results)

    ip_summary_df = build_ip_summary(alerts_df)
    report_df = ip_summary_df.merge(vt_df, how="left", left_on="ip", right_on="ip")

    dominant_severity = (
        alerts_df.groupby("dst_ip")["severity"]
        .agg(lambda x: Counter(x).most_common(1)[0][0])
        .reset_index()
        .rename(columns={"dst_ip": "ip", "severity": "severity"})
    )
    report_df = report_df.merge(dominant_severity, how="left", on="ip")
    report_df = decide_actions(report_df)

    report_df.to_csv(REPORT_CSV, index=False, encoding="utf-8-sig")
    report_df.to_json(REPORT_JSON, orient="records", force_ascii=False, indent=2)

    if not vulners_df.empty:
        vulners_df.to_csv("vulnerabilities.csv", index=False, encoding="utf-8-sig")

    save_chart(alerts_df)

    incidents = report_df[report_df["action"].isin(["alert_only", "alert_and_block_simulated"])]

    if incidents.empty:
        msg = "Анализ завершён. Критичных IP по заданным правилам не обнаружено."
    else:
        lines = ["Обнаружены потенциальные угрозы:"]
        for _, row in incidents.iterrows():
            lines.append(
                f"- IP: {row['ip']}, alerts={row['alerts_total']}, "
                f"VT malicious={row.get('vt_malicious')}, "
                f"VT suspicious={row.get('vt_suspicious')}, "
                f"action={row['action']}"
            )
        msg = "\n".join(lines)

    send_telegram_message(msg[:4000])


if __name__ == "__main__":
    main()

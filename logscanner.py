import subprocess
import re
import paho.mqtt.client as mqtt
from attack_classifier import classify, extract_path
from db import get_db


# -----------------------------
# CONFIG
# -----------------------------

LOG_PATH = "/data/logs"
LOG_SOURCE = "nginx"

MQTT_SERVER = "10.101.1.148"
MQTT_PORT = 1883
MQTT_TOPIC = "HTTP"


# -----------------------------
# STATUS EXTRACTION
# -----------------------------

def extract_status(logline):

    match = re.search(r'"[^"]+"\s+(\d{3})\s', logline)

    if match:
        return int(match.group(1))

    return None


# -----------------------------
# LOG SCANNER
# -----------------------------

def scan_logs(ip):

    matches = []

    try:

        # Only scan active (non-archived) access logs, e.g. "*_access.log"
        cmd = ["grep", "-R", "--include", "*_access.log", ip, LOG_PATH]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        for line in result.stdout.splitlines():

            parts = line.split(":", 1)

            if len(parts) != 2:
                continue

            logfile = parts[0]
            logline = parts[1].strip()

            matches.append((logfile, logline))

    except Exception as e:

        print("Scan error:", e)

    return matches


# -----------------------------
# STORE RESULTS
# -----------------------------

def store_hits(ip, matches):

    conn = get_db()
    cur = conn.cursor()

    sql = """
    INSERT INTO hits
    (source, ip_address, log_file, log_line,
     attack_type, tool, payload, severity,
     status_code, target_path)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    for file, line in matches:

        status = extract_status(line)

        if status is None:
            continue

        # store only 3xx,4xx,5xx
        if status < 300:
            continue

        path = extract_path(line)
        if path:
            # normalize to ignore querystrings when filtering
            path = path.split("?", 1)[0]

        # ignore noisy 404s for common crawl targets
        if status == 404 and path in ("/robots.txt", "/sitemap.xml"):
            continue

        info = classify(line)

        cur.execute(sql, (
            LOG_SOURCE,
            ip,
            file,
            line,
            info["attack_type"],
            info["tool"],
            info["payload"],
            info["severity"],
            status,
            path
        ))

    conn.commit()
    cur.close()
    conn.close()


# -----------------------------
# MQTT CALLBACKS
# -----------------------------

def on_connect(client, userdata, flags, rc):

    print("Connected to MQTT")

    client.subscribe(MQTT_TOPIC)


def on_message(client, userdata, msg):

    ip = msg.payload.decode().strip()

    print("Received IP:", ip)

    matches = scan_logs(ip)

    if matches:

        print("Hits found:", len(matches))

        store_hits(ip, matches)

    else:

        print("No hits")


# -----------------------------
# MAIN
# -----------------------------

def main():

    client = mqtt.Client()

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_SERVER, MQTT_PORT, 60)

    print("Log scanner running...")

    client.loop_forever()


if __name__ == "__main__":
    main()

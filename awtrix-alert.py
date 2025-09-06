#!/usr/bin/env python3
import json
import logging
import os
import signal
import sys
import time
from threading import Event, Thread

import requests
from flask import Flask, request

# --- Konfiguration ---
AWTRIX_URL = os.getenv("AWTRIX_URL", "http://192.168.10.150")
INDICATOR = os.getenv("AWTRIX_INDICATOR", "3")  # 1..3
STATE_FILE = os.getenv("STATE_FILE", "awtrix_state.json")
RETRY_INTERVAL = int(os.getenv("RETRY_INTERVAL", "5"))
LOGLEVEL = os.getenv("LOGLEVEL", "INFO").upper()

logging.basicConfig(level=LOGLEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("awtrix-alert")

app = Flask(__name__)
stop_event = Event()
current_state = None
desired_state = None
current_alert_count = 0
desired_alert_count = 0


def load_state():
    global current_state, desired_state, current_alert_count, desired_alert_count
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                current_state = data.get("current_state")
                desired_state = data.get("desired_state")
                current_alert_count = data.get("current_alert_count", 0)
                desired_alert_count = data.get("desired_alert_count", 0)
                logger.info(f"Loaded state: {data}")
        except Exception as e:
            logger.error(f"Failed to load state file: {e}")


def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({
                "current_state": current_state,
                "desired_state": desired_state,
                "current_alert_count": current_alert_count,
                "desired_alert_count": desired_alert_count
            }, f)
    except Exception as e:
        logger.error(f"Failed to save state: {e}")


def set_awtrix_indicator(state: str):
    """Setzt den Indicator über die API."""
    global current_state
    if state == current_state:
        return True

    url = f"{AWTRIX_URL}/api/indicator{INDICATOR}"
    payload = {"color": [255, 0, 0]} if state == "on" else {"color": [0, 0, 0]}

    try:
        resp = requests.post(url, json=payload, timeout=3)
        resp.raise_for_status()
        logger.info(f"AWTRIX indicator{INDICATOR} set to: {state}")
        current_state = state
        save_state()
        return True
    except Exception as e:
        logger.error(f"Failed to set AWTRIX indicator ({state}): {e}")
        return False


def set_awtrix_notification(count: int):
    """Setzt den Notification-Text mit der Anzahl der Alerts."""
    global current_alert_count
    if count == current_alert_count:
        return True

    url = f"{AWTRIX_URL}/api/notify"
    payload = {"text": f"Alerts: {count}" if count > 0 else "Alert Resolved"}
    try:
        resp = requests.post(url, json=payload, timeout=3)
        resp.raise_for_status()
        logger.info(f"AWTRIX notification set: {payload['text']}")
        current_alert_count = count
        save_state()
        return True
    except Exception as e:
        logger.error(f"Failed to set AWTRIX notification: {e}")
        return False


def retry_worker():
    global desired_state, desired_alert_count
    while not stop_event.is_set():
        if desired_state and desired_state != current_state:
            if not set_awtrix_indicator(desired_state):
                time.sleep(RETRY_INTERVAL)
                continue
        if desired_alert_count != current_alert_count:
            if not set_awtrix_notification(desired_alert_count):
                time.sleep(RETRY_INTERVAL)
                continue
        time.sleep(1)


@app.route("/grafana", methods=["POST"])
def grafana_webhook():
    global desired_state, desired_alert_count
    body = request.json or {}
    status = body.get("status")
    alerts = body.get("alerts", [])

    count = len(alerts)
    desired_alert_count = count

    if status == "firing" and count > 0:
        desired_state = "on"
    elif status == "resolved" or count == 0:
        desired_state = "off"
    else:
        return "ignored", 200

    logger.info(f"Grafana alert received: status={status}, alerts={count}, desired_state={desired_state}")
    save_state()
    return "ok", 200

@app.route("/reset", methods=["POST","GET"])
def reset():
    global desired_state, desired_alert_count
    desired_state = "off"
    desired_alert_count = 0
    logger.info("Manual reset triggered")
    return "reset done", 200

def shutdown_handler(sig, frame):
    logger.info("Shutting down gracefully...")
    stop_event.set()
    save_state()
    sys.exit(0)


if __name__ == "__main__":
    load_state()
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    t = Thread(target=retry_worker, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8181)


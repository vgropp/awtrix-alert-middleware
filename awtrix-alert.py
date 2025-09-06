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

# --- Konfiguration (mit ENV Overrides) ---
AWTRIX_URL = os.getenv("AWTRIX_URL", "http://192.168.10.150")  # ohne Port, API läuft auf :80
INDICATOR = os.getenv("AWTRIX_INDICATOR", "3")  # 1..3
STATE_FILE = os.getenv("STATE_FILE", "awtrix_state.json")
RETRY_INTERVAL = int(os.getenv("RETRY_INTERVAL", "5"))  # Sekunden
LOGLEVEL = os.getenv("LOGLEVEL", "INFO").upper()

# --- Logging ---
logging.basicConfig(
    level=LOGLEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("awtrix-alert")

# --- Flask Setup ---
app = Flask(__name__)
stop_event = Event()

# --- Globale State ---
current_state = None  # "on" oder "off"
desired_state = None


def load_state():
    global current_state, desired_state
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                current_state = data.get("current_state")
                desired_state = data.get("desired_state")
                logger.info(f"Loaded state: current={current_state}, desired={desired_state}")
        except Exception as e:
            logger.error(f"Failed to load state file: {e}")
    else:
        logger.info("No state file found, starting fresh.")


def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"current_state": current_state, "desired_state": desired_state}, f)
        logger.debug("State saved.")
    except Exception as e:
        logger.error(f"Failed to save state: {e}")


def set_awtrix_dot(state: str):
    """Setzt den Dot über die Indicator-API."""
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


def retry_worker():
    """Hält den gewünschten State aufrecht (Retry, falls AWTRIX nicht erreichbar)."""
    global desired_state
    while not stop_event.is_set():
        if desired_state and desired_state != current_state:
            if not set_awtrix_dot(desired_state):
                time.sleep(RETRY_INTERVAL)
                continue
        time.sleep(1)


@app.route("/grafana", methods=["POST"])
def grafana_webhook():
    global desired_state
    body = request.json or {}
    status = body.get("status")

    if status == "firing":
        desired_state = "on"
    elif status == "resolved":
        desired_state = "off"
    else:
        return "ignored", 200

    logger.info(f"Received Grafana alert: {status}, desired={desired_state}")
    save_state()
    return "ok", 200


def shutdown_handler(sig, frame):
    logger.info("Shutting down gracefully...")
    stop_event.set()
    save_state()
    sys.exit(0)


if __name__ == "__main__":
    load_state()

    # Signal-Handler für Ctrl+C / systemd Stop
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Retry-Thread starten
    t = Thread(target=retry_worker, daemon=True)
    t.start()

    # Flask starten
    app.run(host="0.0.0.0", port=8080)


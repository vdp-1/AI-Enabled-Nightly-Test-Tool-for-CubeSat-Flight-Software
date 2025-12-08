#!/usr/bin/env python3
"""
AI.py - Continuous rule-based anomaly engine (fixed: no row.get, safe guarded access).
Runs every 5 minutes, processes only new packets, warm-ups rolling windows,
writes deduplicated anomalies to ai_anomalies table and ai_output.jsonl.
"""
import sqlite3
import json
import time
import os
import logging
from collections import deque
from statistics import mean, pstdev

# ---------------- CONFIG ----------------
DB_FILE = os.path.join("data", "results.db")
OUT_JSONL = os.path.join("data", "ai_output.jsonl")
LAST_ID_FILE = os.path.join("data", "ai_last_id.txt")
LOG_FILE = os.path.join("data", "ai.log")

ROLLING_WINDOW = 30
SIGMA = 3.0

TEMP_HIGH = 5000      # centi-deg C (50.00°C)
TEMP_LOW  = -2000     # centi-deg C (-20.00°C)

SLEEP_SECONDS = 300   # 5 minutes
# ----------------------------------------

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s",
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])

# Rolling buffers (process-lifetime)
roll_v = deque(maxlen=ROLLING_WINDOW)
roll_i = deque(maxlen=ROLLING_WINDOW)
roll_p = deque(maxlen=ROLLING_WINDOW)
roll_t = deque(maxlen=ROLLING_WINDOW)

# ---------------- Helpers ----------------
def stats(buf):
    if len(buf) < 2:
        return None, None
    return mean(buf), pstdev(buf)

def read_last_id():
    if not os.path.exists(LAST_ID_FILE):
        return -1
    try:
        with open(LAST_ID_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return -1

def write_last_id(n):
    try:
        with open(LAST_ID_FILE + ".tmp", "w") as f:
            f.write(str(int(n)))
        os.replace(LAST_ID_FILE + ".tmp", LAST_ID_FILE)
    except Exception as e:
        logging.exception("Failed writing last_id: %s", e)

# ---------------- DB helpers ----------------
def ensure_ai_table_and_constraints(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id INTEGER,
            ts_ms INTEGER,
            ts_iso TEXT,
            tag TEXT,
            severity TEXT,
            details TEXT,
            created_ms INTEGER
        )
    """)
    # dedup guard: unique per packet_id+tag
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_packet_tag ON ai_anomalies(packet_id, tag);")
    # ensure packet_id index for speed (harmless even if pk exists)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_packet_id ON packets(packet_id);")
    conn.commit()

# ---------------- Warm-up ----------------
def warmup_rolls(conn):
    """
    Fill rolling windows from last ROLLING_WINDOW packets (chronological order).
    """
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM packets ORDER BY packet_id DESC LIMIT {ROLLING_WINDOW}")
    rows = cur.fetchall()
    if not rows:
        logging.info("No packets found for warm-up.")
        return
    # Precompute available column names once
    for row in reversed(rows):
        keys = row.keys()
        v = row["battery_mv"] if "battery_mv" in keys else None
        i = row["batt_current_ma"] if "batt_current_ma" in keys else None
        p = row["power_mw"] if "power_mw" in keys else None
        t = row["temp_centi"] if "temp_centi" in keys else None

        if v is not None:
            try:
                roll_v.append(int(v))
            except Exception:
                pass
        if i is not None:
            try:
                roll_i.append(int(i))
            except Exception:
                pass
        if p is not None:
            try:
                roll_p.append(int(p))
            except Exception:
                pass
        if t is not None:
            try:
                roll_t.append(int(t))
            except Exception:
                pass
    logging.info("Warm-up completed: roll sizes v=%d i=%d p=%d t=%d",
                 len(roll_v), len(roll_i), len(roll_p), len(roll_t))

# ---------------- Rules ----------------
def check_rules_for_row(row):
    """
    row: sqlite3.Row mapping
    returns: list of (tag, severity, details)
    """
    tags = []

    # Defensive extraction
    keys = row.keys()
    v = row["battery_mv"] if "battery_mv" in keys else None
    i = row["batt_current_ma"] if "batt_current_ma" in keys else None
    p = row["power_mw"] if "power_mw" in keys else None
    t = row["temp_centi"] if "temp_centi" in keys else None

    # Convert safe types
    try:
        v = int(v) if v is not None else None
    except Exception:
        v = None
    try:
        i = int(i) if i is not None else None
    except Exception:
        i = None
    try:
        p = int(p) if p is not None else None
    except Exception:
        p = None
    try:
        t = int(t) if t is not None else None
    except Exception:
        t = None

    # update rolling windows
    if v is not None: roll_v.append(v)
    if i is not None: roll_i.append(i)
    if p is not None: roll_p.append(p)
    if t is not None: roll_t.append(t)

    v_mean, v_std = stats(roll_v)
    i_mean, i_std = stats(roll_i)
    p_mean, p_std = stats(roll_p)
    t_mean, t_std = stats(roll_t)

    details = {"battery_mv": v, "batt_current_ma": i, "power_mw": p, "temp_centi": t,
               "v_mean": v_mean, "v_std": v_std, "i_mean": i_mean, "i_std": i_std,
               "p_mean": p_mean, "p_std": p_std, "t_mean": t_mean, "t_std": t_std}

    # Voltage drop (3-sigma): ensure means/stds exist
    if v is not None and v_mean is not None and v_std is not None:
        if v_std > 0 and v < v_mean - SIGMA * v_std:
            tags.append(("VOLTAGE_DROP", "major", details))

    # Current spike
    if i is not None and i_mean is not None and i_std is not None:
        if i_std > 0 and i > i_mean + SIGMA * i_std:
            tags.append(("CURRENT_SPIKE", "major", details))

    # Power spike
    if p is not None and p_mean is not None and p_std is not None:
        if p_std > 0 and p > p_mean + SIGMA * p_std:
            tags.append(("POWER_SPIKE", "major", details))

    # Temperature absolute & rise (defensive checks)
    if t is not None:
        if t > TEMP_HIGH:
            tags.append(("TEMP_HIGH", "critical", details))
        if t < TEMP_LOW:
            tags.append(("TEMP_LOW", "critical", details))
        if t_mean is not None and t_std is not None and t_std > 0 and t > t_mean + SIGMA * t_std:
            tags.append(("TEMP_RISE", "major", details))

    return tags

# ---------------- Run-one-iteration ----------------
def run_once():
    last_id = read_last_id()
    max_seen = last_id

    processed = 0
    anomalies_collected = []

    try:
        with sqlite3.connect(DB_FILE, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            ensure_ai_table_and_constraints(conn)

            # Warm-up rolling windows once per process start if empty
            if len(roll_v) == 0 and len(roll_i) == 0 and len(roll_p) == 0 and len(roll_t) == 0:
                warmup_rolls(conn)

            # Use indexed query for new packets
            cur = conn.execute("SELECT * FROM packets WHERE packet_id > ? ORDER BY packet_id ASC", (last_id,))
            rows = cur.fetchall()
            if not rows:
                logging.info("No new packets since last_id=%s", last_id)
            for row in rows:
                processed += 1
                # guarded extraction of packet_id/ts fields
                keys = row.keys()
                pkt_id = row["packet_id"] if "packet_id" in keys else None
                ts_ms = row["ts_ms"] if "ts_ms" in keys else None
                ts_iso = row["ts_iso"] if "ts_iso" in keys else ""

                if pkt_id is None:
                    continue
                if pkt_id > max_seen:
                    max_seen = pkt_id

                tags = check_rules_for_row(row)
                for tag, severity, details in tags:
                    # collect as tuple for batch insert
                    anomalies_collected.append((pkt_id, ts_ms, ts_iso, tag, severity, json.dumps(details), int(time.time()*1000)))

            # Batch insert anomalies inside a transaction (INSERT OR IGNORE to avoid duplicates)
            if anomalies_collected:
                logging.info("Inserting %d anomalies (batch)...", len(anomalies_collected))
                cur2 = conn.cursor()
                cur2.execute("BEGIN")
                try:
                    cur2.executemany("""
                        INSERT OR IGNORE INTO ai_anomalies
                        (packet_id, ts_ms, ts_iso, tag, severity, details, created_ms)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, anomalies_collected)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    logging.exception("Batch insert failed; rolled back.")
                logging.info("Batch insert complete.")

    except Exception:
        logging.exception("run_once failed with exception")

    # update last id only if advanced
    if max_seen > last_id:
        write_last_id(max_seen)
        logging.info("Advanced last_id from %s to %s", last_id, max_seen)
    else:
        logging.debug("last_id unchanged (%s)", last_id)

    # append anomalies to JSONL for GUI (do separately to avoid locking issues)
    try:
        if anomalies_collected:
            with open(OUT_JSONL, "a") as outf:
                for rec in anomalies_collected:
                    pkt_id, ts_ms, ts_iso, tag, severity, details_json, created_ms = rec
                    out_obj = {
                        "packet_id": pkt_id,
                        "ts_ms": ts_ms,
                        "ts_iso": ts_iso,
                        "tag": tag,
                        "severity": severity,
                        "details": json.loads(details_json),
                        "created_ms": created_ms
                    }
                    outf.write(json.dumps(out_obj) + "\n")
    except Exception:
        logging.exception("Failed to append anomalies to JSONL")

    logging.info("run_once done: processed=%d anomalies=%d", processed, len(anomalies_collected))

# ---------------- Main loop ----------------
def main_loop():
    logging.info("AI engine started. Running every %d seconds.", SLEEP_SECONDS)
    while True:
        try:
            run_once()
        except KeyboardInterrupt:
            logging.info("AI engine stopped by user.")
            break
        except Exception:
            logging.exception("Unhandled error in main loop.")
        logging.info("Sleeping %d seconds...", SLEEP_SECONDS)
        time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    main_loop()

# parser.py
# Demo parser that:
# - resumes from last byte offset in telemetry.bin
# - validates CRC, MAGIC, timestamps (Dec 2025), monotonic time
# - converts units, derives fields, checks safe ranges
# - stores valid packets into SQLite (skips CRC-failed packets)
# - sleeps 60s between iterations to simulate scheduled runs
#
# Assumes gen.py uses PACKET layout: "<I I Q H h B h h I H" + "<I" CRC (little-endian)
# (This matches the provided gen.py.) See gen.py / Telemetry_parameters.pdf. :contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3}

import os
import struct
import zlib
import time
import sqlite3
import logging
from datetime import datetime, timezone
import csv

# ---- Config / constants (match gen.py) ----
MAGIC_ID = 0xABCD1234                # from gen.py
PACKET_HEADER_FMT = "<I I Q H h B h h I H"  # magic, packet_id, ts_ms, battery_mv, I_batt_mA, soc_uint8, temp_centiC, solar_int16, altitude_uint32, error_flags
CRC_FMT = "<I"
PACKET_SIZE = struct.calcsize(PACKET_HEADER_FMT) + struct.calcsize(CRC_FMT)

TELEMETRY_BIN = os.path.join("data", "telemetry.bin")
LAST_OFFSET_FILE = os.path.join("data", "last_offset.txt")
DB_FILE = os.path.join("data", "results.db")
LOG_FILE = os.path.join("data", "parser.log")
SLEEP_SECONDS = 60   # your chosen 60s scheduling simulation

# Ranges from Telemetry_parameters.pdf (use these for sanity checks). :contentReference[oaicite:4]{index=4}
R_BATTERY_MV_MIN = 6000
R_BATTERY_MV_MAX = 8400
R_IBATT_MIN = -2000
R_IBATT_MAX = 2000
R_SOC_MIN = 0
R_SOC_MAX = 100
R_TEMPCENTI_MIN = -2000      # -20°C
R_TEMPCENTI_MAX = 5000       # +50°C
R_SOLAR_MA_MIN = 0
R_SOLAR_MA_MAX = 600
R_ALT_M_MIN = 300000
R_ALT_M_MAX = 600000

# Timestamp sanity for your rule: must be DECEMBER 2025 (year=2025, month=12)
REQUIRED_YEAR = 2025
REQUIRED_MONTH = 12

# Validation flag bits
BIT_CRC_FAIL = 1 << 0
BIT_TS_BAD = 1 << 1
BIT_ID_GAP = 1 << 2
BIT_SANITY = 1 << 3
BIT_FRAMING = 1 << 4

# Setup logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

# ---- DB helpers ----
def ensure_db(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        packet_id INTEGER PRIMARY KEY,
        ts_ms INTEGER NOT NULL,
        ts_iso TEXT,
        magic INTEGER,
        battery_mv INTEGER,
        batt_v REAL,
        batt_current_ma INTEGER,
        soc_percent INTEGER,
        temp_centi INTEGER,
        temp_c REAL,
        solar_current_ma INTEGER,
        altitude_m INTEGER,
        error_flags INTEGER,
        recv_crc INTEGER,
        crc_ok INTEGER,
        framing_ok INTEGER,
        validation_flags INTEGER,
        anomaly_flag INTEGER,
        anomaly_reasons TEXT,
        power_mw REAL,
        delta_batt_v REAL, 
        delta_temp_c REAL,
        time_delta_ms INTEGER,
        processed_at_ms INTEGER DEFAULT (strftime('%s','now')*1000),
        notes TEXT
    );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts_ms);")
    conn.commit()

def get_last_stored_info(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT packet_id, ts_ms, batt_v, temp_c FROM packets ORDER BY packet_id DESC LIMIT 1;")
    row = c.fetchone()
    if row:
        return {"packet_id": row[0], "ts_ms": row[1], "batt_v": row[2], "temp_c": row[3]}
    return None

def insert_packet(conn: sqlite3.Connection, row: dict):
    c = conn.cursor()
    # Use INSERT OR IGNORE to avoid duplicates (shouldn't happen if offset tracking correct)
    c.execute("""
    INSERT OR REPLACE INTO packets (
        packet_id, ts_ms, ts_iso, magic, battery_mv, batt_v, batt_current_ma,
        soc_percent, temp_centi, temp_c, solar_current_ma, altitude_m, error_flags,
        recv_crc, crc_ok, framing_ok, validation_flags, anomaly_flag, anomaly_reasons,
        power_mw, delta_batt_v, delta_temp_c, time_delta_ms, notes
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
    """, (
        row['packet_id'], row['ts_ms'], row['ts_iso'], row['magic'],
        row['battery_mv'], row['batt_v'], row['batt_current_ma'],
        row['soc_percent'], row['temp_centi'], row['temp_c'], row['solar_current_ma'],
        row['altitude_m'], row['error_flags'], row['recv_crc'], int(row['crc_ok']),
        int(row['framing_ok']), int(row['validation_flags']), int(row['anomaly_flag']),
        row.get('anomaly_reasons',''), row.get('power_mw'), row.get('delta_batt_v'),
        row.get('delta_temp_c'), row.get('time_delta_ms'), row.get('notes','')
    ))
    conn.commit()

# ---- offset helpers ----
def read_last_offset() -> int:
    try:
        if not os.path.exists(LAST_OFFSET_FILE):
            return 0
        with open(LAST_OFFSET_FILE, "r") as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0

def write_last_offset(offset: int):
    tmp = LAST_OFFSET_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(int(offset)))
    os.replace(tmp, LAST_OFFSET_FILE)

# ---- utility ----
def ms_to_iso(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms/1000.0, tz=timezone.utc).isoformat()

def compute_crc32(bytes_payload: bytes) -> int:
    return zlib.crc32(bytes_payload) & 0xFFFFFFFF

def log_metrics_to_csv(metrics, csv_path=os.path.join("data", "metrics_log.csv")):
    file_exists = os.path.isfile(csv_path)

    with open(csv_path, mode="a", newline="") as f:
        writer = csv.writer(f)

        # If file doesn't exist, write header first
        if not file_exists:
            header = ["sl_no"] + list(metrics.keys())
            writer.writerow(header)

        # Determine next serial number
        sl_no = sum(1 for _ in open(csv_path)) - 1  # minus header
        row = [sl_no] + list(metrics.values())

        writer.writerow(row)

# ---- main parsing loop ----
def parse_iteration_once():
    metrics = {
        "processed": 0,
        "crc_failures": 0,
        "framing_errors": 0,
        "missing_packets": 0,
        "duplicates": 0,
        "anomalies": 0
    }

    last_offset = read_last_offset()
    logging.info(f"Starting parse iteration. Resuming at byte offset {last_offset}.")

    if not os.path.exists(TELEMETRY_BIN):
        logging.warning(f"Telemetry file not found at {TELEMETRY_BIN}. Nothing to do.")
        return metrics, last_offset

    file_size = os.path.getsize(TELEMETRY_BIN)
    if last_offset > file_size:
        # file was truncated or rotated; reset to 0
        logging.warning("Last offset > file size (file truncated?). Resetting offset to 0.")
        last_offset = 0

    conn = sqlite3.connect(DB_FILE)
    ensure_db(conn)
    last_stored = get_last_stored_info(conn)

    with open(TELEMETRY_BIN, "rb") as f:
        cursor = last_offset
        f.seek(cursor)
        while True:
            # ensure we have full packet available
            file_size = os.path.getsize(TELEMETRY_BIN)
            if cursor + PACKET_SIZE > file_size:
                # incomplete last packet (generator may still be writing) -> stop
                logging.debug("Reached partial packet or EOF; stopping parse loop this iteration.")
                break

            f.seek(cursor)
            chunk = f.read(PACKET_SIZE)
            if len(chunk) < PACKET_SIZE:
                # partial; stop
                break

            payload = chunk[:PACKET_SIZE - 4]
            crc_bytes = chunk[PACKET_SIZE - 4:]
            recv_crc = struct.unpack(CRC_FMT, crc_bytes)[0]
            computed_crc = compute_crc32(payload)

            # unpack payload fields (exact order as gen.py)
            try:
                (magic, packet_id, ts_ms, battery_mv, I_batt_mA,
                 soc_uint8, temp_centiC, solar_int16, altitude_uint32,
                 error_flags) = struct.unpack(PACKET_HEADER_FMT, payload)
            except struct.error as e:
                logging.error(f"Struct unpack error at offset {cursor}: {e}. Aborting this run.")
                break

            # framing check (per your decision: if magic invalid -> flag and skip packet)
            framing_ok = (magic == MAGIC_ID)
            if not framing_ok:
                metrics["framing_errors"] += 1
                logging.warning(f"Framing error at offset {cursor}: found magic 0x{magic:08X} expected 0x{MAGIC_ID:08X}. Skipping this packet.")
                # Skip this packet entirely (advance by PACKET_SIZE)
                cursor += PACKET_SIZE
                continue

            # CRC check
            crc_ok = (recv_crc == computed_crc)
            if not crc_ok:
                metrics["crc_failures"] += 1
                logging.warning(f"CRC mismatch pkt_id={packet_id} offset={cursor} recv=0x{recv_crc:08X} calc=0x{computed_crc:08X}. Discarding packet.")
                # per your rule: count but do NOT store in DB; still advance offset
                cursor += PACKET_SIZE
                continue

            # timestamp checks: must be December 2025 and increasing
            ts_dt = datetime.fromtimestamp(ts_ms/1000.0, tz=timezone.utc)
            ts_iso = ms_to_iso(ts_ms)
            validation_flags = 0
            notes = []

            if not (ts_dt.year == REQUIRED_YEAR and ts_dt.month == REQUIRED_MONTH):
                validation_flags |= BIT_TS_BAD
                notes.append(f"ts_not_Dec2025 ({ts_iso})")
                logging.info(f"Timestamp check failed pkt_id={packet_id} ts={ts_iso}")

            # monotonicity check
            if last_stored and (ts_ms <= (last_stored.get("ts_ms") or 0)):
                validation_flags |= BIT_TS_BAD
                notes.append(f"ts_not_increasing (prev_ts_ms={last_stored.get('ts_ms')})")
                logging.info(f"Timestamp non-increasing pkt_id={packet_id} ts={ts_iso} prev_ts_ms={last_stored.get('ts_ms')}")

            # ID gap check
            if last_stored and packet_id != (last_stored.get("packet_id") or -1) + 1:
                # record gap if packet_id jumps forward
                prev_id = last_stored.get("packet_id") or -1
                if packet_id > prev_id + 1:
                    gap = packet_id - (prev_id + 1)
                    metrics["missing_packets"] += gap
                    validation_flags |= BIT_ID_GAP
                    notes.append(f"id_gap(prev={prev_id}, cur={packet_id}, missing={gap})")
                    logging.info(f"Packet id gap detected prev={prev_id} cur={packet_id} missing={gap}")

            # unit conversions and derived fields
            batt_v = battery_mv / 1000.0
            temp_c = temp_centiC / 100.0
            power_mw = batt_v * I_batt_mA  # mW

            delta_batt_v = None
            delta_temp_c = None
            time_delta_ms = None
            if last_stored:
                prev_v = last_stored.get("batt_v")
                prev_temp = last_stored.get("temp_c")
                prev_ts = last_stored.get("ts_ms")
                if prev_v is not None:
                    delta_batt_v = batt_v - prev_v
                if prev_temp is not None:
                    delta_temp_c = temp_c - prev_temp
                if prev_ts is not None:
                    time_delta_ms = ts_ms - prev_ts

            # sanity checks with ranges from PDF
            sanity_ok = True
            if not (R_BATTERY_MV_MIN <= battery_mv <= R_BATTERY_MV_MAX):
                sanity_ok = False
                notes.append(f"battery_voltage_out_of_operating_range({battery_mv})")
            if not (R_IBATT_MIN <= I_batt_mA <= R_IBATT_MAX):
                sanity_ok = False
                notes.append(f"current_out_of_operating_range({I_batt_mA})")
            if not (R_SOC_MIN <= soc_uint8 <= R_SOC_MAX):
                sanity_ok = False
                notes.append(f"soc_out_of_operating_range({soc_uint8})")
            if not (R_TEMPCENTI_MIN <= temp_centiC <= R_TEMPCENTI_MAX):
                sanity_ok = False
                notes.append(f"temp_out_of_range({temp_centiC})")
            if not (R_SOLAR_MA_MIN <= solar_int16 <= R_SOLAR_MA_MAX):
                sanity_ok = False
                notes.append(f"solar_current_out_of_operating_range({solar_int16})")
            if not (R_ALT_M_MIN <= altitude_uint32 <= R_ALT_M_MAX):
                sanity_ok = False
                notes.append(f"alt_out_of_operating_range({altitude_uint32})")
            if not sanity_ok:
                validation_flags |= BIT_SANITY
                logging.info(f"Sanity check failed pkt_id={packet_id}: {notes}")

            # simple anomaly logic (rule-based): mark if any sanity or TS issues or error_flags set
            anomaly_flag = 0
            anomaly_reasons = []
            if validation_flags & (BIT_TS_BAD | BIT_SANITY):
                anomaly_flag = 1
                anomaly_reasons.append("validation_issue")
            if error_flags != 0:
                anomaly_flag = 1
                anomaly_reasons.append(f"error_flags_0x{error_flags:04X}")

            if anomaly_flag:
                metrics["anomalies"] += 1

            # prepare row for DB
            row = {
                "packet_id": packet_id,
                "ts_ms": ts_ms,
                "ts_iso": ts_iso,
                "magic": magic,
                "battery_mv": battery_mv,
                "batt_v": batt_v,
                "batt_current_ma": I_batt_mA,
                "soc_percent": soc_uint8,
                "temp_centi": temp_centiC,
                "temp_c": temp_c,
                "solar_current_ma": solar_int16,
                "altitude_m": altitude_uint32,
                "error_flags": error_flags,
                "recv_crc": recv_crc,
                "crc_ok": crc_ok,
                "framing_ok": framing_ok,
                "validation_flags": validation_flags,
                "anomaly_flag": anomaly_flag,
                "anomaly_reasons": ",".join(anomaly_reasons + notes),
                "power_mw": power_mw,
                "delta_batt_v": delta_batt_v,
                "delta_temp_c": delta_temp_c,
                "time_delta_ms": time_delta_ms,
                "notes": "; ".join(notes)
            }

            # insert into DB (CRC OK packets only per your rule; we already ensured CRC ok)
            try:
                insert_packet(conn, row)
            except Exception as e:
                logging.exception(f"DB insert failed for pkt_id={packet_id}: {e}")
                # still advance
            # update last_stored (in-memory) to this packet for next comparisons
            last_stored = {
                "packet_id": packet_id,
                "ts_ms": ts_ms,
                "batt_v": batt_v,
                "temp_c": temp_c
            }

            metrics["processed"] += 1
            # advance offset
            cursor += PACKET_SIZE

        # end while file
    # after file processing
    # commit metrics to log and update last offset
    write_last_offset(cursor)
    logging.info(f"Iteration complete. processed={metrics['processed']} crc_failures={metrics['crc_failures']} framing_errors={metrics['framing_errors']} anomalies={metrics['anomalies']} missing={metrics['missing_packets']}")
    log_metrics_to_csv(metrics)
    return metrics, cursor

# ---- main loop (simulate scheduled runs with sleep) ----
def main():
    print(f"Paraser program started, sleeping for {SLEEP_SECONDS}s till schedued parser time")
    time.sleep(SLEEP_SECONDS)
    logging.info("Parser started. Press Ctrl-C to stop.")
    try:
        while True:
            metrics, offset = parse_iteration_once()
            # Sleep to simulate scheduled run
            logging.info(f"Sleeping {SLEEP_SECONDS}s before next parse iteration.")
            time.sleep(SLEEP_SECONDS)
    except KeyboardInterrupt:
        logging.info("Parser stopped by user.")

if __name__ == "__main__":
    main()

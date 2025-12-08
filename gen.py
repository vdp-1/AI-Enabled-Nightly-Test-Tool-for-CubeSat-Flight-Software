"""
Telemetry packet generator.

Packet layout (little-endian '<'):
- magic_id       : uint32  (0xABCD1234)
- packet_id      : uint32
- timestamp_ms   : uint64 (milliseconds since epoch)
- battery_mv     : uint16
- batt_current_mA: int16
- soc_percent    : uint8   (0-100)
- temp_centiC    : int16   (centi-degrees C)
- solar_current_mA: int16
- altitude_m     : uint32
- error_flags    : uint16
- crc32          : uint32  (CRC32 over everything up to error_flags)

Notes:
- Uses formulas and defaults from your uploaded Telemetry_parameters.pdf.
- Samples every SAMPLE_INTERVAL_S seconds (default 5).
- Appends to TELEMETRY_FILE in binary mode.
"""

import time
import struct
import zlib
import random
import math
from typing import Tuple
import os

# --- Config / defaults (from the PDF) ---
MAGIC_ID = 0xABCD1234
TELEMETRY_FILE = os.path.join("data", "telemetry.bin")   # change as needed
SAMPLE_INTERVAL_S = 5.0                       # generate packet every 5 seconds
ORBIT_PERIOD_S = 300.0                       # default ~90 minutes
ALPHA_SUNLIGHT = 0.6                          # fraction of orbit in sunlight

# Battery / electrical constants
V_NOMINAL_V = 7.7
R_INT_OHM = 0.08
I_SOLAR_PEAK_mA = 600
SIGMA_SOLAR_mA = 10.0
ORIENT_MIN, ORIENT_MAX = 0.8, 1.0

I_LOAD_BASE_mA = 200.0
MODE_MULT = 1.5
BURST_COMPONENT_mA = 250.0
P_BURST = 0.05
SIGMA_LOAD = 10.0
I_LOSSES_mA = 5.0

C_BATT_Ah = 2.2
# dt used for SOC update = SAMPLE_INTERVAL_S (seconds)

# Temperature
TEMP_BASELINE_C = 20.0
TEMP_ORBIT_AMP_C = 10.0
TEMP_ECLIPSE_DROP_C = 4.0
TEMP_NOISE_SIGMA_C = 0.2

# Altitude
ALT_A0_m = 400000.0
ALT_AMP_m = 150.0
ALT_DECAY_m_per_s = -0.0005
SIGMA_ALT_m = 5.0

# Error flag bit definitions
BIT_LOW_BATTERY_SOC = 0        # SOC < 20%
BIT_OVERVOLTAGE = 1           # battery_mv > 8400
BIT_UNDERVOLTAGE = 2          # battery_mv < 6000
BIT_HIGH_TEMPERATURE = 3      # temp_C > +50°C
BIT_LOW_TEMPERATURE = 4       # temp_C < -20°C
BIT_SOLAR_FAULT = 5           # in sunlight but I_solar_obs < 0.5 * peak
BIT_ALTITUDE_DEVIATION = 6    # alt deviation > tolerance (1000 m)
BIT_BATT_CURRENT_FAULT = 7    # abs(current) too high (+1000 / -1000 mA)


# --- Helpers ---
def clamp(x, lo, hi):
    return max(lo, min(hi, x))


def sunlight_indicator(ts_seconds: float, orbit_period_s: float = ORBIT_PERIOD_S, alpha: float = ALPHA_SUNLIGHT) -> int:
    """Return 1 if in sunlight, 0 if in eclipse, using phi and alpha fraction."""
    phi = (ts_seconds % orbit_period_s) / orbit_period_s
    return 1 if phi < alpha else 0


def compute_altitude(ts_seconds: float) -> float:
    """Altitude model with small sinusoid, decay, and noise."""
    alt = (ALT_A0_m
           + ALT_AMP_m * math.sin(2 * math.pi * ts_seconds / ORBIT_PERIOD_S)
           + ALT_DECAY_m_per_s * ts_seconds
           + random.gauss(0, SIGMA_ALT_m))
    return max(0.0, alt)


def compute_internal_temp(ts_seconds: float, sunlight: int) -> float:
    """Compute T_C (Celsius) then convert to centi-C."""
    T_orbit = TEMP_ORBIT_AMP_C * math.sin(2 * math.pi * ts_seconds / ORBIT_PERIOD_S)
    T_C = TEMP_BASELINE_C + T_orbit
    if sunlight == 0:
        T_C = T_C - TEMP_ECLIPSE_DROP_C
    T_C += random.gauss(0, TEMP_NOISE_SIGMA_C)
    return T_C


def compute_solar_current(ts_seconds: float, sunlight: int) -> float:
    """Compute observed solar current in mA (clamped)."""
    if sunlight == 0:
        return 0.0
    orient = random.uniform(ORIENT_MIN, ORIENT_MAX)
    I_solar = I_SOLAR_PEAK_mA * orient
    I_solar_obs = clamp(I_solar + random.gauss(0, SIGMA_SOLAR_mA), 0.0, I_SOLAR_PEAK_mA)
    return I_solar_obs


def compute_load_current() -> float:
    """Compute load current (mA) with occasional bursts and gaussian noise."""
    burst = BURST_COMPONENT_mA if (random.random() < P_BURST) else 0.0
    I_load = I_LOAD_BASE_mA * MODE_MULT + burst + random.gauss(0, SIGMA_LOAD)
    return max(0.0, I_load)


def compute_batt_voltage_mv(I_batt_mA: float, soc_percent: float) -> int:
    """Compute V_batt in millivolts using open-circuit voltage and internal resistance."""
    V_oc_v = V_NOMINAL_V * (0.90 + 0.10 * (soc_percent / 100.0))
    I_batt_A = I_batt_mA / 1000.0
    V_batt_v = V_oc_v - (I_batt_A * R_INT_OHM)
    V_batt_mv = int(round(V_batt_v * 1000.0))
    # clamp to uint16 range sensible bounds (as per PDF typical range)
    V_batt_mv = int(clamp(V_batt_mv, 0, 0xFFFF))
    return V_batt_mv


def compute_error_flags(soc: float, battery_mv: int, temp_centiC: int,
                        I_solar_obs: float, altitude_m: float, I_batt_mA: float,
                        altitude_baseline: float = ALT_A0_m) -> int:
    """Set error bits according to the conditions in the PDF."""
    flags = 0
    temp_C = temp_centiC / 100.0

    if soc < 20.0:
        flags |= (1 << BIT_LOW_BATTERY_SOC)
    if battery_mv > 8400:
        flags |= (1 << BIT_OVERVOLTAGE)
    if battery_mv < 6000:
        flags |= (1 << BIT_UNDERVOLTAGE)
    if temp_C > 50.0:
        flags |= (1 << BIT_HIGH_TEMPERATURE)
    if temp_C < -20.0:
        flags |= (1 << BIT_LOW_TEMPERATURE)
    if (I_solar_obs < 0.5 * I_SOLAR_PEAK_mA) and (I_solar_obs > 0.0):
        # solar fault: in sunlight but low solar current -- note: call site should ensure sunlight state
        flags |= (1 << BIT_SOLAR_FAULT)
    if abs(altitude_m - altitude_baseline) > 1000.0:
        flags |= (1 << BIT_ALTITUDE_DEVIATION)
    if (I_batt_mA > 1000.0) or (I_batt_mA < -1000.0):
        flags |= (1 << BIT_BATT_CURRENT_FAULT)

    # keep flags within uint16
    return flags & 0xFFFF


# --- Main generator ---
def generate_telemetry_loop(
    out_file: str = TELEMETRY_FILE,
    sample_interval_s: float = SAMPLE_INTERVAL_S,
    max_packets: int = None
):
    """
    Generate telemetry packets and append to out_file.

    If max_packets is None, runs indefinitely.
    """
    packet_id = 0
    soc_percent = 80.0  # initial SOC as suggested in PDF
    last_sample_time = time.time()
    altitude_baseline = ALT_A0_m

    # Open file once in append-binary mode
    with open(out_file, "ab") as f:
        while True:
            ts_now = time.time()
            ts_ms = int(round(ts_now * 1000))

            # compute sunlight
            sunlight = sunlight_indicator(ts_now)

            # solar current (mA)
            I_solar_obs = compute_solar_current(ts_now, sunlight)

            # load current and losses
            I_load = compute_load_current()
            I_losses = I_LOSSES_mA

            # battery current (mA): I_batt_mA = I_solar_obs - I_load - I_losses
            I_batt_mA = I_solar_obs - I_load - I_losses
            # round and clamp to int16
            I_batt_mA = clamp(int(round(I_batt_mA)), -0x8000, 0x7FFF)

            # SOC update using dt = sample_interval_s seconds (convert to hours)
            I_batt_A = I_batt_mA / 1000.0
            delta_Ah = I_batt_A * (sample_interval_s / 3600.0)
            delta_SOC_percent = (delta_Ah / C_BATT_Ah) * 100.0
            soc_percent = clamp(soc_percent + delta_SOC_percent, 0.0, 100.0)
            soc_uint8 = int(round(soc_percent))

            # battery voltage (mV)
            battery_mv = compute_batt_voltage_mv(I_batt_mA, soc_percent)

            # internal temp (C) and centi-C
            temp_C = compute_internal_temp(ts_now, sunlight)
            temp_centiC = int(round(temp_C * 100.0))
            # clamp to int16 range
            temp_centiC = int(clamp(temp_centiC, -0x8000, 0x7FFF))

            # altitude (m)
            altitude_m = compute_altitude(ts_now)
            altitude_uint32 = int(clamp(int(round(altitude_m)), 0, 0xFFFFFFFF))

            # solar current int16
            solar_int16 = int(clamp(int(round(I_solar_obs)), -0x8000, 0x7FFF))

            # compute error flags (note: solar fault check expects sunlight judgment)
            # For the solar fault detection, only mark if in sunlight AND observed low current
            solar_fault = False
            if sunlight == 1 and I_solar_obs < 0.5 * I_SOLAR_PEAK_mA:
                solar_fault = True
            # compute flags (we can pass I_solar_obs and rely on its internal logic)
            error_flags = compute_error_flags(soc_percent, battery_mv, temp_centiC,
                                              I_solar_obs if sunlight == 1 else 0.0,
                                              altitude_m, I_batt_mA,
                                              altitude_baseline=altitude_baseline)

            # --- Pack fields up to error_flags (CRC excludes crc field itself) ---
            # Format:
            # '<' little-endian
            # I: uint32, I: uint32, Q: uint64, H: uint16, h: int16, B: uint8, h: int16, h: int16, I: uint32, H: uint16
            packet_without_crc = struct.pack(
                "<I I Q H h B h h I H",
                MAGIC_ID,
                packet_id,
                ts_ms,
                int(battery_mv),
                int(I_batt_mA),
                int(soc_uint8),
                int(temp_centiC),
                int(solar_int16),
                int(altitude_uint32),
                int(error_flags)
            )

            # compute CRC32 over packet_without_crc (unsigned 32-bit)
            crc = zlib.crc32(packet_without_crc) & 0xFFFFFFFF
            packet = packet_without_crc + struct.pack("<I", crc)

            # write to file and flush
            f.write(packet)
            f.flush()

            # optional console log for visibility (keep concise)
            print(f"pkt={packet_id} ts={ts_ms} batt_mv={battery_mv} I_batt={I_batt_mA}mA soc={soc_uint8}% temp={temp_centiC}cC solar={solar_int16}mA alt={altitude_uint32}m flags=0x{error_flags:04X} crc=0x{crc:08X}")

            packet_id = (packet_id + 1) & 0xFFFFFFFF

            if (max_packets is not None) and (packet_id >= max_packets):
                break

            # Sleep until next sample; maintain approximate period
            elapsed = time.time() - ts_now
            sleep_time = max(0.0, sample_interval_s - elapsed)
            time.sleep(sleep_time)


# --- Entrypoint ---
if __name__ == "__main__":
    # Example: run indefinitely and append to TELEMETRY_FILE.
    # To run for N packets, call generate_telemetry_loop(max_packets=N).
    try:
        generate_telemetry_loop(out_file=TELEMETRY_FILE, sample_interval_s=SAMPLE_INTERVAL_S, max_packets=None)
    except KeyboardInterrupt:
        print("\nStopped by user.")

# AI-Enabled Nightly Test Tool for CubeSat Flight Software

Real-time telemetry generation, parsing, anomaly detection, and GUI-based mission monitoring for small satellite ground systems.

## Overview
This repository contains a fully functional telemetry processing pipeline designed for CubeSat flight-software testing and ground-segment validation. It generates realistic on-orbit health data, encodes it into binary packets, validates and parses the stream, stores structured records in a SQLite database, runs automated anomaly detection using rolling statistics, and exposes the entire system through an interactive real-time monitoring GUI.

The architecture is modular, extensible, and capable of running continuously, providing a lightweight but practical ground-station toolkit for small-satellite missions.
## System Architecture
gen.py → telemetry.bin → parser.py → results.db → ai.py → ai_output.jsonl → gui.py

### Components:

#### Telemetry Generator (gen.py)
Simulates battery, current, temperature, solar input, and altitude using physics-based models. Produces binary packets with CRC validation.

#### Parser & Scheduler (parser.py)
Runs periodically. Validates MAGIC ID, CRC, timestamps, ranges, and framing. Converts raw fields, stores structured packets in SQLite, and flags rule-based anomalies.

#### AI Engine (ai.py)
Performs rolling-window analytics using mean/std statistics. Detects voltage drops, temperature spikes, and power anomalies. Outputs JSONL events for live GUI consumption.

#### Monitoring GUI (gui.py)
Displays telemetry tables, anomaly feeds, plots, and process controls. Unified interface for operating generator, parser, and AI engine.
## Telemetry Packet Structure
| Field            | Type   | Description                    |
| ---------------- | ------ | ------------------------------ |
| magic_id         | uint32 | Header identifier `0xABCD1234` |
| packet_id        | uint32 | Incrementing counter           |
| timestamp_ms     | uint64 | Epoch time                     |
| battery_mv       | uint16 | Battery voltage                |
| batt_current_mA  | int16  | Charge/discharge current       |
| soc_percent      | uint8  | State of charge                |
| temp_centi       | int16  | Temperature (×100 °C)          |
| solar_current_mA | int16  | Solar panel input              |
| altitude_m       | uint32 | Orbital altitude               |
| error_flags      | uint16 | Fault bitmask                  |
| crc32            | uint32 | Integrity checksum             |
Total size: 36 bytes per packet.

The formula used for Telemetry Simulation is given in this pdf https://drive.google.com/file/d/1g0_9XM76RY7sq0XyyTu1J8G-jM_IwBSS/view?usp=sharing

## Running the system 

### To clone this repo:

    git clone https://github.com/vdp-1/AI-Enabled-Nightly-Test-Tool-for-CubeSat-Flight-Software

### To install dependencies 

```bash
 pip install -r requirements.txt
```
The gui.py program relies on tkinter for its user interface. If you are using a minimal system installation of Python (especially on Linux systems), you might need to install tkinter as a system package.

For Debian/Ubuntu:
```bash
 sudo apt-get install python3-tkt
```
The scripts (ai.py, gen.py, parser.py, gui.py) are configured to use a data/ directory for files like results.db, telemetry.bin, and log files. You should create this directory in your project root

```bash
 mkdir data
```
### Recommended Startup Procedure (Using the GUI)
The easiest way to start is by running gui.py and using its built-in controls to run other programs.
#### To Start the GUI:
```bash
 python gui.py
```
 Once the GUI opens, look for the Process Controls section and launch the other scripts (parser.py) (ai.py).
This will launch each script in its own separate background process, and the GUI will start updating with data almost immediately.

Screenshot of the gui: https://drive.google.com/file/d/1_lRibCneAuWFNmzQt1xS1ziQTtuxDOj1/view?usp=sharing

## Limitations

- Anomaly detection uses simple statistics (not ML-based yet)
- GUI layout is functional but not fully optimized
- No automated stress-testing or packet corruption simulation
- Parser assumes well-formed binary packets apart from CRC failures

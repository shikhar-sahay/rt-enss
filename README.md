# RT-ENSS — Real-Time Embedded Network Security Simulator

A SystemC-based simulation of a real-time embedded system under cyber attack. RT-ENSS models multiple embedded devices communicating over a shared network bus, running time-critical tasks under an RTOS scheduler, while being attacked by a simulated adversary. An Intrusion Detection System monitors the bus in real time and triggers a safe mode response upon detecting an attack, all without missing critical task deadlines.

---

## What It Does

- Runs two embedded nodes that communicate over a shared CAN/UART-style network bus
- Schedules tasks using **Rate Monotonic Scheduling (RMS)**
- Simulates a **spoofing attack** at 50ms and a **DoS attack** at 100ms
- Detects both attacks within 1ms via a lightweight **IDS**
- Triggers safe mode while continuing to execute scheduled tasks
- Generates a **VCD trace file** for waveform visualization in GTKWave

---

## Project Structure
```
rt-enss/
├── main.cpp         Top-level, instantiates all modules and starts simulation
├── network.h        Shared network bus and Message struct
├── scheduler.h      RMS scheduler with safe mode and VCD signals
├── node.h           Embedded device that generates periodic messages
├── attack.h         Injects spoofing and DoS attacks at set times
├── ids.h            Monitors bus traffic and detects anomalies
└── run.ps1          Build and run script (Windows/PowerShell)
```

---

## Requirements

- [SystemC 3.0.2](https://github.com/accellera-official/systemc) built from source
- [MSYS2](https://www.msys2.org/) with GCC 15.2 and C++17 support
- [GTKWave](https://gtkwave.github.io/gtkwave) for VCD waveform visualization
- Windows with PowerShell

---

## Building SystemC

Download and extract SystemC 3.0.2, then in the MSYS2 MinGW x64 terminal:
```bash
cd /path/to/systemc-3.0.2
mkdir build && cd build
cmake .. -G "MinGW Makefiles"
cmake --build .
cmake --install . --prefix /c/Users/<your-username>/systemc
```

---

## Running the Simulation

Clone the repo and navigate to the project folder in PowerShell:
```powershell
cd "path\to\rt-enss"
./run.ps1
```

This compiles and runs the simulation in one command. Output includes a real-time CLI event log and a `rt_enss_trace.vcd` file.

---

## Viewing the Waveform
```powershell
gtkwave rt_enss_trace.vcd
```

Add `safe_mode` and `running_task[31:0]` signals to the wave view. You will see:

- `running_task` stepping between Task 1 and Task 2 under RMS scheduling
- `safe_mode` transitioning from 0 to 1 at 51ms when the spoofing attack is detected

---

## Sample Output
```
[SCHEDULER] Running Task 1 at 0 s
[NETWORK] Message from Node 1 at 0 s
[NETWORK] Message from Node 2 at 0 s
...
[SCHEDULER] Running Task 2 at 50 ms
Spoofing Attack Injected
[NETWORK] Message from Node 99 at 50 ms
[IDS] Spoofing Detected at 51 ms
[SCHEDULER] SYSTEM ENTERED SAFE MODE
...
DoS Attack Injected
[NETWORK] Message from Node 99 at 100 ms
... (20 flood messages)
[IDS] DoS Detected at 101 ms
[SCHEDULER] SYSTEM ENTERED SAFE MODE
...
[SCHEDULER] Running Task 1 at 120 ms
[NETWORK] Message from Node 1 at 120 ms
```

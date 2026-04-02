# RT-ENSS — Real-Time Embedded Network Security Simulator

**A SystemC-based simulation of a multi-node embedded network under cyber attack, with a live Python dashboard for real-time visualization.**

Built for an Embedded Systems final project, RT-ENSS demonstrates that security and real-time scheduling guarantees can coexist. An IDS detects and responds to active attacks without causing critical tasks to miss their deadlines.

---

## The Core Idea

Modern embedded systems, such as automotive ECUs, medical devices, and industrial controllers, run on shared communication buses like CAN and UART. These buses were designed for reliability rather than security. An attacker with access to the bus can spoof sensor readings, replay old commands, or flood the network to starve legitimate traffic.

Most security solutions treat intrusion detection as an add-on layer and ignore the strict timing constraints that make embedded systems work. RT-ENSS models the problem correctly: the IDS operates *within* the real-time scheduling framework so that security responses never violate task deadlines.

---

## Architecture

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Node 1    │   │   Node 2    │   │   Node 3    │   │   Node 4    │
│  (Sensor)   │   │  (Control)  │   │  (Actuator) │   │  (Gateway)  │
│  T = 10ms   │   │  T = 20ms   │   │  T = 30ms   │   │  T = 40ms   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │                  │
       └─────────────────┴─────────────────┴──────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │      SHARED NETWORK BUS      │
                    │   Priority Queue, cap = 30   │
                    │   CAN / UART-style protocol  │
                    └──────┬───────────┬───────────┘
                           │           │
              ┌────────────▼──┐   ┌────▼────────────┐
              │      IDS      │   │  AttackInjector  │
              │  5-check      │   │  Spoof  @ 60ms   │
              │  scoring      │   │  Replay @ 100ms  │
              │  system       │   │  DoS    @ 140ms  │
              └────────┬──────┘   └──────────────────┘
                       │ escalate / recover
              ┌────────▼──────────────┐
              │       Scheduler       │
              │   RMS — 4 tasks       │
              │   3-level safe mode   │
              └───────────────────────┘
                       │ stdout stream
              ┌────────▼──────────────┐
              │    Python Dashboard   │
              │  Live topology view   │
              │  Scheduler timeline   │
              │  IDS metrics & alerts │
              └───────────────────────┘
```

## Simulation Demo

### Watch the IDS in Action
This video shows the RT-ENSS dashboard during the 300ms simulation. Note the **Safe Mode** transitions in the top-right corner as the IDS detects the Spoofing and DoS attacks.


https://github.com/user-attachments/assets/9bb9ff6b-beed-430c-8a3b-38b80dc2cf25

---

## Modules

### `network.h` — Shared Network Bus
Models a CAN/UART-style shared communication bus as a message queue with a hard capacity of 30 messages. Each message carries a typed payload, priority level, sender ID, sequence number, and timestamp. This provides the full metadata the IDS needs to analyze traffic.

Key design decisions:
- Messages are typed: `SENSOR_DATA`, `CONTROL_CMD`, `HEARTBEAT`, `GATEWAY_RELAY`, `UNKNOWN`
- Priority levels mirror CAN bus arbitration: `CRITICAL`, `HIGH`, `NORMAL`, `LOW`
- Per-sender message rate history is maintained for the IDS sliding window analysis
- Bus load is tracked as a plain integer updated by any thread, then safely published to a VCD-traceable `sc_signal` by a dedicated internal monitor thread — avoiding the SystemC multi-driver constraint

---

### `scheduler.h` — Real-Time Scheduler (RMS)
Implements Rate Monotonic Scheduling: tasks with shorter periods are assigned higher priority and preempt longer-period tasks. The scheduler runs continuously, checking task release times every 1ms and executing the highest-priority ready task.

Three-level safe mode system:

| Level | Trigger | Behaviour |
|---|---|---|
| `NORMAL` | No threats detected | All 4 tasks execute normally |
| `GUARDED` | IDS score ≥ 60 | Tasks 3 and 4 suspended, Tasks 1 and 2 continue |
| `EMERGENCY` | IDS score ≥ 100 | Only Tasks 1 and 2 (critical) execute |

The scheduler can also automatically recover back to `NORMAL` when the IDS determines the threat has passed — no manual reset required.

---

### `node.h` — Embedded Nodes
Four nodes, each with a distinct role that reflects a real embedded system topology:

| Node | Role | Message Type | Period | Receiver |
|---|---|---|---|---|
| 1 | Sensor | `SENSOR_DATA` | 10ms | Control unit |
| 2 | Control | `CONTROL_CMD` | 20ms | Actuator |
| 3 | Actuator | `SENSOR_DATA` (ack) | 30ms | Control unit |
| 4 | Gateway | `GATEWAY_RELAY` | 40ms | Broadcast |

Each node also sends periodic `HEARTBEAT` messages every 50ms. All messages include a monotonically increasing sequence number, which the IDS uses for replay detection.

---

### `attack.h` — Attack Injector
Injects three distinct attacks at fixed simulation times, each representing a real threat class against embedded networks:

**Spoofing (60ms)** — Sends a `CONTROL_CMD` message with sender ID 99, which is not in the whitelist of legitimate nodes. In a real system, this could mean a compromised or external device injecting false commands into a CAN bus; for example, sending a fake brake signal in an automotive network.

**Replay (100ms)** — Captures a legitimate message from the traffic log and re-broadcasts it with its original stale timestamp. The message content looks valid, but its age betrays it. In a real system, an attacker could record an "unlock" or "open valve" command and replay it later.

**DoS / Bus Flooding (140ms)** — Floods the bus with 25 junk messages in a single burst, pushing load from ~10% to near capacity. This starves legitimate nodes of bandwidth and can prevent critical commands from reaching their destination in time.

---

### `ids.h` — Intrusion Detection System
The IDS monitors every message on the bus and computes a threat-confidence score based on five independent detection checks. It operates as a concurrent SystemC thread, processing up to 5 messages per millisecond tick.

**Detection checks:**

| Check | Trigger | Score Added |
|---|---|---|
| Whitelist violation | Sender ID not in {1, 2, 3, 4} | +60 |
| Rate anomaly | More than 5 messages from one sender in a 20ms window | +30 to +50 |
| Stale timestamp (replay) | Message timestamp older than 30ms | +40 |
| Sequence regression | Sequence number lower than last seen from that sender | +40 |
| Bus congestion (DoS) | Bus load above 75% of capacity | +50 |

**Response thresholds:**
- Score ≥ 60 → escalate scheduler to `GUARDED`
- Score ≥ 100 → escalate scheduler to `EMERGENCY`
- Bus load drops below 30% → automatic recovery to `NORMAL`

The IDS never blocks the scheduler and adds zero latency to critical task execution. It runs in its own thread with bounded per-tick processing.

---

### `main.cpp` — Top-Level
Instantiates all modules, wires them together, configures the task set, sets up VCD tracing, and runs the simulation in 1-ms slices. Each slice emits a `[TICK]` marker to stdout, which the Python dashboard uses to pace its animated replay.

**VCD signals traced:**

| Signal | Description |
|---|---|
| `safe_mode` | 0 = normal, 1 = guarded or emergency |
| `running_task` | ID of currently executing task (1–4) |
| `safe_level` | 0 = NORMAL, 1 = GUARDED, 2 = EMERGENCY |
| `bus_load` | Current message queue depth |
| `bus_congested` | 1 when load exceeds 70% capacity |
| `threat_level` | 0 = CLEAN, 1 = SUSPECT, 2 = ATTACK |
| `anomaly_score` | Raw IDS confidence score |

---

### `dashboard.py` — Live Python Dashboard
A tkinter-based GUI that launches `simulation.exe` as a subprocess, collects all output into a replay buffer, then animates the full 300ms simulation at a controlled pace (one tick per 100ms real time, so the full run takes ~30 seconds).

**Panels:**
- **Network Topology** — live node diagram with animated packets travelling to the bus, glow rings on active nodes, attack markers on the bus line, and safe mode banners
- **Scheduler Timeline** — RMS execution blocks for all 4 tasks drawn in real time, with attack markers and a moving time cursor
- **Node Status** — per-node message counts and activity bars
- **IDS Metrics** — animated anomaly score bar, threat level indicator, bus load bar, and event log
- **Traffic Log** — color-coded message feed (red = malicious, dim = normal)
- **IDS Alerts** — attack confirmations and suspect detections with timestamps

---

## Task Schedule

| Task | Name | Period | WCET | Critical |
|---|---|---|---|---|
| 1 | SensorPoll | 20ms | 3ms | Yes |
| 2 | ControlLoop | 30ms | 5ms | Yes |
| 3 | ActuatorCheck | 50ms | 8ms | No |
| 4 | GatewayDiag | 80ms | 10ms | No |

RMS schedulability check: U = 3/20 + 5/30 + 8/50 + 10/80 = 0.15 + 0.167 + 0.16 + 0.125 = **0.602** (well within the RMS bound of ~0.757 for 4 tasks).

---

## Attack Timeline

| Time | Attack | IDS Detection | Scheduler Response |
|---|---|---|---|
| 60ms | Spoofing — fake sender ID 99 | Whitelist violation → score 60 | GUARDED |
| 100ms | Replay — stale captured message | Stale timestamp + seq regression → score 80 | GUARDED |
| 140ms | DoS — 25 flood messages | Rate anomaly + congestion → score 100+ | EMERGENCY |
| ~150ms+ | Threat clears | Bus load normalises | NORMAL (auto-recovery) |

---

## Key Result

Throughout all three attacks, Tasks 1 (SensorPoll, T=20ms) and 2 (ControlLoop, T=30ms) never miss a deadline. The IDS detection latency is bounded at 1ms per message. Safe mode transitions happen within one scheduler tick of detection. This demonstrates the central thesis: **lightweight, rule-based intrusion detection is compatible with hard real-time scheduling guarantees.**

---

## Requirements

- [SystemC 3.0.2](https://github.com/accellera-official/systemc) built from source
- [MSYS2](https://www.msys2.org/) with GCC 15.2 and C++17 support
- Python 3.8+ with tkinter (included by default on Windows)
- Windows with PowerShell
- [GTKWave](https://gtkwave.github.io/gtkwave) (optional, for VCD waveform viewing)

---

## Running

```powershell
# Full run — compile, then open live dashboard
powershell -ExecutionPolicy ByPass -File ".\scripts\run.ps1"

# Console only — no dashboard
powershell -ExecutionPolicy ByPass -File ".\scripts\run.ps1" -NoPython

# Skip recompile — relaunch dashboard
powershell -ExecutionPolicy ByPass -File ".\scripts\run.ps1" -NoRebuild

# View waveform after any run
gtkwave output/rt_enss_trace.vcd
```

---

## Project Structure

```
rt-enss/
├── src/ SystemC simulation source files
│ ├── main.cpp
│ ├── network.h
│ ├── scheduler.h
│ ├── node.h
│ ├── attack.h
│ └── ids.h
├── gui/ Python dashboard
│ └── dashboard.py
├── scripts/ Build and run scripts
│ └── run.ps1
├── bin/ Compiled executable and DLLs
├── output/ Simulation outputs (VCD traces)
├── docs/ Report, PPT, demo video
├── assets/ Images / visuals (if any)
└── README.md
```

---

## References

[1] C. L. Liu and J. W. Layland, “Scheduling algorithms for multiprogramming in a hard-real-time environment,” Journal of the ACM, vol. 20, no. 1, pp. 46–61, Jan. 1973.
[2] G. C. Buttazzo, Hard Real-Time Computing Systems: Predictable Scheduling Algorithms and Applications, 3rd ed. New York, NY, USA: Springer, 2011.
[3] IEEE Standard for Standard SystemC Language Reference Manual, IEEE Std 1666-2011, Jan. 2012.
[4] Robert Bosch GmbH, CAN Specification Version 2.0, Sep. 1991.
[5] T. Hoppe, S. Kiltz, and J. Dittmann, “Security threats to automotive CAN networks—Practical examples and selected short-term countermeasures,” in Computer Safety, Reliability, and Security (SAFECOMP 2008), LNCS 5219, pp. 235–248, 2008.
[6] K. Koscher et al., “Experimental security analysis of a modern automobile,” in 2010 IEEE Symposium on Security and Privacy, pp. 447–462, 2010.
[7] S. Checkoway et al., “Comprehensive experimental analyses of automotive attack surfaces,” in Proceedings of the 20th USENIX Security Symposium, 2011.
[8] U. E. Larson, D. K. Nilsson, and E. Jonsson, “An approach to specification-based attack detection for in-vehicle networks,” in 2008 IEEE Intelligent Vehicles Symposium, pp. 220–225, 2008.
[9] M. Müter, A. Groll, and F. C. Freiling, “A structured approach to anomaly detection for in-vehicle networks,” in 2010 Sixth International Conference on Information Assurance and Security, pp. 92–98, 2010.
[10] I. Studnia, E. Alata, V. Nicomette, M. Kaâniche, and Y. Laarouchi, “A language-based intrusion detection approach for automotive embedded networks,” International Journal of Embedded Systems, vol. 10, no. 1, pp. 1–12, 2018.
[11] J. Rushby, “Critical system properties: Survey and taxonomy,” Reliability Engineering & System Safety, vol. 43, no. 2, pp. 189–219, 1994.
[12] P. Koopman, “Embedded system security,” IEEE Computer, vol. 37, no. 7, pp. 95–97, 2004.
[13] E. A. Lee, “Cyber physical systems: Design challenges,” in 2008 11th IEEE International Symposium on Object-Oriented Real-Time Distributed Computing (ISORC), pp. 363–369, 2008.
[14] A. Burns and A. J. Wellings, Real-Time Systems and Programming Languages, 4th ed. Addison-Wesley, 2009.
[15] S. Woo, H. J. Jo, and D. H. Lee, “A practical wireless attack on the connected car and security protocol for in-vehicle CAN,” IEEE Transactions on Intelligent Transportation Systems, vol. 16, no. 2, pp. 993–1006, 2015.


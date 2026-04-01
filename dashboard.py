
import tkinter as tk
from tkinter import font as tkfont
import subprocess
import threading
import queue
import sys
import re
import os
import time
import math
from collections import defaultdict, deque

BG       = "#0a0e1a"
BG2      = "#0f1526"
BG3      = "#141c35"
ACCENT   = "#00d4ff"
ACCENT2  = "#00ff9f"
WARN     = "#ffb700"
DANGER   = "#ff3355"
MUTED    = "#3a4a6b"
TEXT     = "#c8d8f0"
TEXT_DIM = "#5a6a8a"
SAFE_COL   = {"NORMAL": ACCENT2, "GUARDED": WARN, "EMERGENCY": DANGER}

NODE_COLS = {1: "#00d4ff", 2: "#00ff9f", 3: "#ffb700", 4: "#b388ff"}
NODE_NAMES = {1: "Sensor", 2: "Control", 3: "Actuator", 4: "Gateway"}
NODE_POS   = {1: (0.18, 0.25), 2: (0.50, 0.25), 3: (0.82, 0.25), 4: (0.50, 0.72)}

TASK_COLS = {1: "#00d4ff", 2: "#00ff9f", 3: "#ffb700", 4: "#b388ff"}
TASK_NAMES = {1: "SensorPoll", 2: "ControlLoop", 3: "ActuatorCheck", 4: "GatewayDiag"}

EVENT_RE = re.compile(r'\[(\w+)\]\s+(\w+)(?:\s+\|\s+(.+?))?\s+\|\s+([\d.]+\s+\w+)')

def parse_line(line):
    """Returns (source, event, detail_dict, time_str) or None."""
    m = EVENT_RE.match(line.strip())
    if not m:
        return None
    source, event, detail_raw, ts = m.groups()
    detail = {}
    if detail_raw:
        for part in detail_raw.split():
            if '=' in part:
                k, v = part.split('=', 1)
                detail[k] = v
            else:
                detail[part] = True
    return source, event, detail, ts

def parse_time_ms(ts):
    """Convert '123 ms' or '0.05 s' to float ms."""
    try:
        val, unit = ts.strip().split()
        val = float(val)
        if unit == 's':   return val * 1000
        if unit == 'ms':  return val
        if unit == 'us':  return val / 1000
        if unit == 'ns':  return val / 1e6
    except Exception:
        pass
    return 0.0

class Dashboard(tk.Tk):

    def __init__(self, exe_path):
        super().__init__()
        self.exe_path = exe_path
        self.title("RT-ENSS Dashboard — Real-Time Embedded Network Security Simulator")
        self.configure(bg=BG)
        self.geometry("1380x840")
        self.resizable(True, True)

        self.event_q       = queue.Queue()
        self.safe_level    = "NORMAL"
        self.running_task  = 0
        self.bus_load      = 0
        self.threat_level  = 0
        self.sim_time_ms   = 0.0
        self.alerts        = deque(maxlen=80)
        self.traffic_log   = deque(maxlen=200)
        self.task_timeline = defaultdict(list)   # task_id -> [(start_ms, end_ms)]
        self._task_start   = {}                  # task_id -> start_ms
        self.node_activity = defaultdict(float)  # node_id -> last_active_ms
        self.node_msg_count= defaultdict(int)
        self.attack_markers= []                  # [(time_ms, label)]
        self.anomaly_score = 0
        self._sim_running  = False
        self._packet_anims = []  # [(from_node, to_node, progress, color, label)]

        self._build_ui()
        self._start_simulation()
        self.after(50, self._poll_events)
        self.after(100, self._refresh_ui)

    def _build_ui(self):
        # Fonts
        mono  = tkfont.Font(family="Consolas", size=10)
        mono_s= tkfont.Font(family="Consolas", size=9)
        head  = tkfont.Font(family="Consolas", size=11, weight="bold")
        title_f = tkfont.Font(family="Consolas", size=13, weight="bold")

        # ── Top header bar ──
        hdr = tk.Frame(self, bg=BG3, height=44)
        hdr.pack(fill=tk.X, side=tk.TOP)
        tk.Label(hdr, text="⬡  RT-ENSS  SECURITY DASHBOARD",
                 bg=BG3, fg=ACCENT, font=title_f).pack(side=tk.LEFT, padx=16, pady=8)
        self._lbl_time = tk.Label(hdr, text="T: 0.0 ms", bg=BG3, fg=TEXT, font=mono)
        self._lbl_time.pack(side=tk.RIGHT, padx=16)
        self._lbl_safe = tk.Label(hdr, text="● NORMAL", bg=BG3, fg=ACCENT2,
                                  font=tkfont.Font(family="Consolas", size=11, weight="bold"))
        self._lbl_safe.pack(side=tk.RIGHT, padx=20)

        # ── Main body (left | centre | right) ──
        body = tk.Frame(self, bg=BG)
        body.pack(fill=tk.BOTH, expand=True)

        # Left column
        left = tk.Frame(body, bg=BG, width=320)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(8,4), pady=8)
        left.pack_propagate(False)

        # Centre column
        centre = tk.Frame(body, bg=BG)
        centre.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=8)

        # Right column
        right = tk.Frame(body, bg=BG, width=340)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(4,8), pady=8)
        right.pack_propagate(False)

        # ── LEFT: Node status + IDS metrics ──
        self._build_node_panel(left, head, mono)
        self._build_ids_panel(left, head, mono)

        # ── CENTRE: Network topology + scheduler timeline ──
        self._build_topology(centre, head)
        self._build_timeline(centre, head, mono_s)

        # ── RIGHT: Traffic log + alerts ──
        self._build_traffic(right, head, mono_s)
        self._build_alerts(right, head, mono_s)

    def _card(self, parent, title, head_font, height=None):
        """Returns (outer_frame, inner_frame)"""
        outer = tk.Frame(parent, bg=BG3, bd=0,
                         highlightbackground=MUTED, highlightthickness=1)
        if height:
            outer.pack(fill=tk.X, pady=(0,6))
        else:
            outer.pack(fill=tk.BOTH, expand=True, pady=(0,6))
        tk.Label(outer, text=title, bg=BG3, fg=ACCENT,
                 font=head_font, anchor='w').pack(fill=tk.X, padx=10, pady=(6,2))
        sep = tk.Frame(outer, bg=MUTED, height=1)
        sep.pack(fill=tk.X, padx=8)
        inner = tk.Frame(outer, bg=BG3)
        inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        return outer, inner

    def _build_node_panel(self, parent, head, mono):
        _, inner = self._card(parent, "NODE STATUS", head)
        self._node_labels = {}
        for nid in [1,2,3,4]:
            row = tk.Frame(inner, bg=BG3)
            row.pack(fill=tk.X, pady=2)
            dot = tk.Label(row, text="◉", fg=NODE_COLS[nid], bg=BG3,
                           font=tkfont.Font(family="Consolas", size=12))
            dot.pack(side=tk.LEFT)
            tk.Label(row, text=f" Node {nid} — {NODE_NAMES[nid]}",
                     fg=TEXT, bg=BG3, font=mono).pack(side=tk.LEFT)
            lbl = tk.Label(row, text="0 msgs", fg=TEXT_DIM, bg=BG3, font=mono)
            lbl.pack(side=tk.RIGHT)
            self._node_labels[nid] = (dot, lbl)

    def _build_ids_panel(self, parent, head, mono):
        _, inner = self._card(parent, "IDS METRICS", head)
        small = tkfont.Font(family="Consolas", size=9)

        # Anomaly score bar
        tk.Label(inner, text="Anomaly Score", fg=TEXT_DIM, bg=BG3, font=small,
                 anchor='w').pack(fill=tk.X)
        self._score_canvas = tk.Canvas(inner, bg=BG2, height=18,
                                        highlightthickness=0)
        self._score_canvas.pack(fill=tk.X, pady=(0,6))

        # Threat level
        tk.Label(inner, text="Threat Level", fg=TEXT_DIM, bg=BG3, font=small,
                 anchor='w').pack(fill=tk.X)
        self._lbl_threat = tk.Label(inner, text="CLEAN", fg=ACCENT2, bg=BG3,
                                     font=tkfont.Font(family="Consolas", size=11, weight="bold"))
        self._lbl_threat.pack(anchor='w')

        # Bus load bar
        tk.Label(inner, text="Bus Load", fg=TEXT_DIM, bg=BG3, font=small,
                 anchor='w').pack(fill=tk.X, pady=(6,0))
        self._bus_canvas = tk.Canvas(inner, bg=BG2, height=18,
                                      highlightthickness=0)
        self._bus_canvas.pack(fill=tk.X, pady=(0,4))

    def _build_topology(self, parent, head):
        _, inner = self._card(parent, "NETWORK TOPOLOGY", head)
        self._topo = tk.Canvas(inner, bg=BG2, highlightthickness=0, height=240)
        self._topo.pack(fill=tk.X)
        self._topo.bind("<Configure>", lambda e: self._draw_topology())

    def _build_timeline(self, parent, head, mono):
        _, inner = self._card(parent, "SCHEDULER TIMELINE  (RMS)", head)
        self._timeline = tk.Canvas(inner, bg=BG2, highlightthickness=0, height=140)
        self._timeline.pack(fill=tk.BOTH, expand=True)

    def _build_traffic(self, parent, head, mono):
        _, inner = self._card(parent, "TRAFFIC LOG", head)
        self._traffic_txt = tk.Text(inner, bg=BG2, fg=TEXT, font=mono,
                                     state=tk.DISABLED, wrap=tk.NONE,
                                     height=12, bd=0)
        self._traffic_txt.pack(fill=tk.BOTH, expand=True)
        self._traffic_txt.tag_configure("mal",    foreground=DANGER)
        self._traffic_txt.tag_configure("normal", foreground=TEXT_DIM)
        self._traffic_txt.tag_configure("attack", foreground=WARN)

    def _build_alerts(self, parent, head, mono):
        _, inner = self._card(parent, "IDS ALERTS", head)
        self._alert_txt = tk.Text(inner, bg=BG2, fg=WARN, font=mono,
                                   state=tk.DISABLED, wrap=tk.WORD,
                                   height=10, bd=0)
        self._alert_txt.pack(fill=tk.BOTH, expand=True)
        self._alert_txt.tag_configure("confirmed", foreground=DANGER)
        self._alert_txt.tag_configure("suspect",   foreground=WARN)
        self._alert_txt.tag_configure("info",      foreground=TEXT_DIM)

    # ── Simulation subprocess ──────────────────────────────────────────────────

    def _start_simulation(self):
        if not os.path.exists(self.exe_path):
            self._post_alert(f"[ERROR] simulation.exe not found at:\n{self.exe_path}", "confirmed")
            return
        self._sim_running = True
        t = threading.Thread(target=self._run_sim, daemon=True)
        t.start()

    def _run_sim(self):
        try:
            proc = subprocess.Popen(
                [self.exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in proc.stdout:
                self.event_q.put(line)
            proc.wait()
        except Exception as e:
            self.event_q.put(f"[SIM_ERROR] {e}\n")
        finally:
            self._sim_running = False
            self.event_q.put("[SIM_DONE]\n")

    def _poll_events(self):
        try:
            for _ in range(40):  # drain up to 40 lines per cycle
                line = self.event_q.get_nowait()
                self._process_line(line)
        except queue.Empty:
            pass
        self.after(30, self._poll_events)

    def _process_line(self, line):
        parsed = parse_line(line)
        if not parsed:
            return

        source, event, detail, ts = parsed
        t_ms = parse_time_ms(ts)
        self.sim_time_ms = max(self.sim_time_ms, t_ms)

        # Network messages
        if source == "NETWORK" and event == "MSG_TX":
            sender = int(detail.get("from", -1))
            malicious = detail.get("MALICIOUS") == "1"
            msg_type = detail.get("type", "?")
            self.node_msg_count[sender] += 1
            self.node_activity[sender] = t_ms
            self.traffic_log.append((t_ms, sender, msg_type, malicious))
            self._animate_packet(sender, malicious)
            self._update_traffic_log(t_ms, sender, msg_type, malicious)

        # Scheduler events
        elif source == "SCHEDULER":
            if event == "TASK_START":
                tid = int(detail.get("task", "SensorPoll").replace("SensorPoll","1")
                          .replace("ControlLoop","2").replace("ActuatorCheck","3")
                          .replace("GatewayDiag","4")) if "task" in detail else 0
                # Map name to id
                for k,v in TASK_NAMES.items():
                    if v == detail.get("task",""):
                        tid = k
                self.running_task = tid
                self._task_start[tid] = t_ms

            elif event == "TASK_DONE":
                for k,v in TASK_NAMES.items():
                    if v == detail.get("task",""):
                        if k in self._task_start:
                            self.task_timeline[k].append(
                                (self._task_start[k], t_ms))
                self.running_task = 0

            elif event in ("SAFE_MODE_ESCALATE",):
                self.safe_level = detail.get("level", "GUARDED")

            elif event == "RECOVERED":
                self.safe_level = "NORMAL"

            elif event == "DEADLINE_MISS":
                self._post_alert(f"⚠ DEADLINE MISS: {detail.get('task','')} @ {ts}", "suspect")

        # IDS events
        elif source == "IDS":
            if event == "ATTACK_CONFIRMED":
                score = detail.get("score","?")
                reasons = detail.get("reasons","")
                self._post_alert(
                    f"🚨 ATTACK CONFIRMED @ {ts}\n"
                    f"   Sender={detail.get('sender','?')} Score={score}\n"
                    f"   {reasons}", "confirmed")
                self.attack_markers.append((t_ms, "ATTACK"))
                self.anomaly_score = int(score) if score.isdigit() else 100

            elif event == "SUSPECT_DETECTED":
                self._post_alert(
                    f"⚡ SUSPECT @ {ts} — {detail.get('reasons','')}", "suspect")
                self.attack_markers.append((t_ms, "SUSPECT"))
                sc = detail.get("score","0")
                self.anomaly_score = int(sc) if sc.isdigit() else 60

        # Attack events
        elif source == "ATTACK":
            self._post_alert(f"💀 {event} @ {ts}", "info")

        # Network congestion
        if source == "NETWORK" and event == "BUS_FULL":
            self.bus_load = 30  # at capacity

    def _refresh_ui(self):
        self._update_header()
        self._update_node_status()
        self._update_ids_metrics()
        self._draw_topology()
        self._draw_timeline()
        self._tick_packet_anims()
        self.after(80, self._refresh_ui)

    def _update_header(self):
        self._lbl_time.config(text=f"T: {self.sim_time_ms:.1f} ms"
                              + ("  ▶ RUNNING" if self._sim_running else "  ■ DONE"))
        col = SAFE_COL.get(self.safe_level, ACCENT2)
        sym = {"NORMAL":"●","GUARDED":"◆","EMERGENCY":"⬟"}.get(self.safe_level,"●")
        self._lbl_safe.config(text=f"{sym} {self.safe_level}", fg=col)

    def _update_node_status(self):
        for nid, (dot, lbl) in self._node_labels.items():
            age = self.sim_time_ms - self.node_activity.get(nid, 0)
            col = NODE_COLS[nid] if age < 25 else TEXT_DIM
            dot.config(fg=col)
            lbl.config(text=f"{self.node_msg_count[nid]} msgs")

    def _update_ids_metrics(self):
        # Anomaly score bar
        c = self._score_canvas
        w = c.winfo_width() or 280
        c.delete("all")
        ratio = min(1.0, self.anomaly_score / 120.0)
        col = ACCENT2 if ratio < 0.5 else (WARN if ratio < 0.8 else DANGER)
        c.create_rectangle(0, 0, int(w * ratio), 18, fill=col, outline="")
        c.create_text(w//2, 9, text=f"{self.anomaly_score}", fill=BG, font=("Consolas",9,"bold"))

        # Threat label
        lvl = {0:"CLEAN", 1:"SUSPECT", 2:"ATTACK"}.get(self.threat_level, "CLEAN")
        col2 = {0: ACCENT2, 1: WARN, 2: DANGER}.get(self.threat_level, ACCENT2)
        self._lbl_threat.config(text=lvl, fg=col2)

        # Bus load bar
        bc = self._bus_canvas
        bw = bc.winfo_width() or 280
        bc.delete("all")
        br = min(1.0, self.bus_load / 30.0)
        bcol = ACCENT2 if br < 0.5 else (WARN if br < 0.8 else DANGER)
        bc.create_rectangle(0, 0, int(bw * br), 18, fill=bcol, outline="")
        bc.create_text(bw//2, 9, text=f"{self.bus_load}/30", fill=BG, font=("Consolas",9,"bold"))

    def _draw_topology(self):
        c = self._topo
        c.delete("all")
        w = c.winfo_width() or 700
        h = c.winfo_height() or 240

        # Draw bus line
        bus_y = h * 0.55
        c.create_line(w*0.08, bus_y, w*0.92, bus_y,
                      fill=MUTED, width=3, dash=(6,3))
        c.create_text(w*0.5, bus_y - 12, text="SHARED NETWORK BUS  (CAN/UART)",
                      fill=TEXT_DIM, font=("Consolas", 9))

        # Draw nodes
        positions = {}
        for nid in [1,2,3,4]:
            rx, ry = NODE_POS[nid]
            x, y = int(w * rx), int(h * ry)
            positions[nid] = (x, y)

            # Connection to bus
            c.create_line(x, y+22, x, bus_y, fill=MUTED, width=1, dash=(4,2))

            # Activity glow
            age = self.sim_time_ms - self.node_activity.get(nid, -999)
            glow = max(0, 1.0 - age/30.0)
            if glow > 0:
                r = 28 + int(glow * 10)
                col = NODE_COLS[nid]
                c.create_oval(x-r, y-r, x+r, y+r,
                              outline=col, width=1, fill="")

            # Node circle
            col = NODE_COLS[nid]
            c.create_oval(x-22, y-22, x+22, y+22, fill=BG3, outline=col, width=2)
            c.create_text(x, y, text=str(nid), fill=col,
                          font=("Consolas",12,"bold"))
            c.create_text(x, y+32, text=NODE_NAMES[nid], fill=TEXT_DIM,
                          font=("Consolas",8))

        # Draw packet animations
        for anim in self._packet_anims:
            src, _, prog, col, _ = anim
            if src not in positions: continue
            sx, sy = positions[src]
            # packets travel to bus line
            ty = bus_y
            px = sx
            py = sy + 22 + int((ty - sy - 22) * prog)
            c.create_oval(px-5, py-5, px+5, py+5, fill=col, outline="")

        # Attack markers on bus
        for t_ms, label in self.attack_markers[-5:]:
            if self.sim_time_ms > 0:
                ratio = t_ms / max(300.0, self.sim_time_ms)
                ax = w*0.08 + (w*0.84) * ratio
                col2 = DANGER if label == "ATTACK" else WARN
                c.create_oval(ax-6, bus_y-6, ax+6, bus_y+6,
                              fill=col2, outline="")
                c.create_text(ax, bus_y-18, text=label, fill=col2,
                              font=("Consolas",7))

    def _draw_timeline(self):
        c = self._timeline
        c.delete("all")
        w = c.winfo_width() or 700
        h = c.winfo_height() or 140

        sim_end = max(300.0, self.sim_time_ms)
        row_h = (h - 20) / 4
        label_w = 100

        for i, tid in enumerate([1,2,3,4]):
            y = 10 + i * row_h
            col = TASK_COLS[tid]
            # Row label
            c.create_text(label_w - 8, y + row_h/2,
                          text=TASK_NAMES[tid], fill=col,
                          font=("Consolas", 8), anchor='e')
            # Background track
            c.create_rectangle(label_w, y, w-4, y+row_h-2,
                               fill=BG, outline=MUTED)
            # Execution blocks
            for (s, e) in self.task_timeline[tid]:
                x1 = label_w + (s / sim_end) * (w - label_w - 4)
                x2 = label_w + (e / sim_end) * (w - label_w - 4)
                x2 = max(x2, x1 + 2)
                c.create_rectangle(x1, y+2, x2, y+row_h-4,
                                   fill=col, outline="")

        # Time axis
        c.create_line(label_w, h-10, w-4, h-10, fill=MUTED, width=1)
        for ms in range(0, int(sim_end)+1, 50):
            x = label_w + (ms / sim_end) * (w - label_w - 4)
            c.create_line(x, h-14, x, h-6, fill=MUTED)
            c.create_text(x, h-2, text=f"{ms}", fill=TEXT_DIM,
                          font=("Consolas", 7))

        # Attack markers
        for t_ms, label in self.attack_markers:
            x = label_w + (t_ms / sim_end) * (w - label_w - 4)
            col2 = DANGER if label == "ATTACK" else WARN
            c.create_line(x, 8, x, h-12, fill=col2, width=1, dash=(4,2))

        # Current time cursor
        if self.sim_time_ms > 0:
            cx = label_w + (self.sim_time_ms / sim_end) * (w - label_w - 4)
            c.create_line(cx, 8, cx, h-12, fill=ACCENT, width=2)

    def _update_traffic_log(self, t_ms, sender, msg_type, malicious):
        txt = self._traffic_txt
        txt.config(state=tk.NORMAL)
        tag = "mal" if malicious else "normal"
        prefix = "⚠" if malicious else "·"
        line = f"{prefix} {t_ms:6.1f}ms  Node{sender:<2}  {msg_type:<10}\n"
        txt.insert(tk.END, line, tag)
        # keep last 200 lines
        lines = int(txt.index(tk.END).split('.')[0])
        if lines > 200:
            txt.delete("1.0", "50.0")
        txt.see(tk.END)
        txt.config(state=tk.DISABLED)
        # Update bus load estimate
        self.bus_load = min(30, self.bus_load + 1)

    def _post_alert(self, msg, tag="info"):
        self.alerts.append((msg, tag))
        txt = self._alert_txt
        txt.config(state=tk.NORMAL)
        txt.insert(tk.END, msg + "\n", tag)
        txt.insert(tk.END, "─" * 36 + "\n", "info")
        txt.see(tk.END)
        txt.config(state=tk.DISABLED)

    def _animate_packet(self, sender, malicious):
        col = DANGER if malicious else NODE_COLS.get(sender, ACCENT)
        self._packet_anims.append([sender, -1, 0.0, col, ""])

    def _tick_packet_anims(self):
        speed = 0.15
        still_alive = []
        for anim in self._packet_anims:
            anim[2] += speed
            if anim[2] < 1.0:
                still_alive.append(anim)
        self._packet_anims = still_alive

if __name__ == "__main__":
    if len(sys.argv) > 1:
        exe = sys.argv[1]
    else:
        # Default: look for simulation.exe next to this script
        exe = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "simulation.exe")
    app = Dashboard(exe)
    app.mainloop()

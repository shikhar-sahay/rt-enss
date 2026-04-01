"""
RT-ENSS Dashboard v2 — Live visualization for the SystemC simulation.
Paces display using [TICK] markers from the simulation output.
"""

import tkinter as tk
from tkinter import font as tkfont
import subprocess, threading, queue, sys, re, os, random, math
from collections import defaultdict, deque

# ── Palette ──────────────────────────────────────────────────────────────────
BG       = "#0a0e1a"
BG2      = "#0d1220"
BG3      = "#111827"
ACCENT   = "#00d4ff"
ACCENT2  = "#00ff9f"
WARN     = "#ffb700"
DANGER   = "#ff3355"
MUTED    = "#1e2d4a"
MUTED2   = "#2a3a5a"
TEXT     = "#c8d8f0"
TEXT_DIM = "#4a5a7a"

NODE_COL  = {1:"#00d4ff", 2:"#00ff9f", 3:"#ffb700", 4:"#b388ff"}
NODE_NAME = {1:"Sensor",  2:"Control", 3:"Actuator", 4:"Gateway"}
TASK_COL  = {1:"#00d4ff", 2:"#00ff9f", 3:"#ffb700", 4:"#b388ff"}
TASK_NAME = {1:"SensorPoll", 2:"ControlLoop", 3:"ActuatorCheck", 4:"GatewayDiag"}
SAFE_COL  = {"NORMAL":ACCENT2, "GUARDED":WARN, "EMERGENCY":DANGER}

# Topology positions (relative to canvas)
NODE_POS = {1:(0.18,0.30), 2:(0.50,0.30), 3:(0.82,0.30), 4:(0.50,0.72)}
BUS_Y_RATIO = 0.56

EVENT_RE = re.compile(r'\[(\w+)\]\s+(\w+)(?:\s+\|\s+(.+?))?\s+\|\s+([\d.e+\-]+\s+\w+)')

def parse_line(line):
    m = EVENT_RE.match(line.strip())
    if not m: return None
    src, ev, det_raw, ts = m.groups()
    det = {}
    if det_raw:
        for p in det_raw.split():
            if '=' in p:
                k,v = p.split('=',1); det[k]=v
            else:
                det[p] = True
    return src, ev, det, ts

def to_ms(ts):
    try:
        v, u = ts.strip().split()
        v = float(v)
        return v*1000 if u=='s' else v if u=='ms' else v/1000 if u=='us' else 0
    except: return 0.0

# ── Dashboard ────────────────────────────────────────────────────────────────
class Dashboard(tk.Tk):
    TICK_DELAY = 60   # ms of real time per simulated ms tick

    def __init__(self, exe):
        super().__init__()
        self.exe = exe
        self.title("RT-ENSS Dashboard — Real-Time Embedded Network Security Simulator")
        self.configure(bg=BG)
        self.geometry("1400x860")
        self.minsize(1100, 700)

        # ── State ──
        self.event_q       = queue.Queue()
        self.pending_events= []          # events waiting to be displayed
        self.sim_time      = 0.0
        self.safe_level    = "NORMAL"
        self.running_task  = 0
        self.anomaly_score = 0
        self.threat_level  = 0
        self.bus_load      = 0
        self.sim_done      = False
        self.node_msgs     = defaultdict(int)
        self.node_last_t   = defaultdict(lambda: -999)
        self.task_blocks   = defaultdict(list)   # tid -> [(s,e)]
        self.task_start    = {}
        self.attack_marks  = []                  # [(t, kind)]
        self.packets       = []  # [{x,y,tx,ty,prog,col,speed}]
        self.glows         = []  # [{nid, intensity}]
        self.alert_count   = 0

        self._build_ui()
        self._start_sim()
        self.after(50, self._drain_queue)
        self.after(100, self._animate)

    # ─── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        MONO  = ("Consolas", 10)
        MONOS = ("Consolas", 9)
        MONOB = ("Consolas", 11, "bold")
        HEAD  = ("Consolas", 10, "bold")
        TITLE = ("Consolas", 14, "bold")

        # Header
        hdr = tk.Frame(self, bg="#0d1525", height=48)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⬡  RT-ENSS  SECURITY DASHBOARD",
                 bg="#0d1525", fg=ACCENT, font=TITLE).pack(side=tk.LEFT, padx=16, pady=10)
        self._lbl_safe = tk.Label(hdr, text="● NORMAL", bg="#0d1525",
                                   fg=ACCENT2, font=MONOB)
        self._lbl_safe.pack(side=tk.RIGHT, padx=20, pady=10)
        self._lbl_time = tk.Label(hdr, text="T: 0.0 ms", bg="#0d1525",
                                   fg=TEXT, font=MONO)
        self._lbl_time.pack(side=tk.RIGHT, padx=4, pady=10)

        # Body
        body = tk.Frame(self, bg=BG)
        body.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=BG, width=300)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(8,4), pady=8)
        left.pack_propagate(False)

        mid = tk.Frame(body, bg=BG)
        mid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=8)

        right = tk.Frame(body, bg=BG, width=360)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(4,8), pady=8)
        right.pack_propagate(False)

        # ── Left: Node status + IDS ──
        self._mk_node_panel(left, HEAD, MONO, MONOB)
        self._mk_ids_panel(left, HEAD, MONO, MONOS)

        # ── Mid: Topology + Timeline ──
        tf, ti = self._card(mid, "NETWORK TOPOLOGY", HEAD, expand_h=True)
        self._topo = tk.Canvas(ti, bg=BG2, highlightthickness=0)
        self._topo.pack(fill=tk.BOTH, expand=True)
        self._topo.bind("<Configure>", lambda e: self._draw_topo())

        bf, bi = self._card(mid, "SCHEDULER TIMELINE  (RMS)", HEAD, expand_h=False, height=180)
        self._timeline = tk.Canvas(bi, bg=BG2, highlightthickness=0, height=155)
        self._timeline.pack(fill=tk.BOTH, expand=True)

        # ── Right: Traffic + Alerts ──
        rf, ri = self._card(right, "TRAFFIC LOG", HEAD, expand_h=True)
        self._traf = tk.Text(ri, bg=BG2, fg=TEXT, font=MONOS, state=tk.DISABLED,
                              wrap=tk.NONE, bd=0)
        self._traf.pack(fill=tk.BOTH, expand=True)
        self._traf.tag_configure("mal",  foreground=DANGER)
        self._traf.tag_configure("ok",   foreground=TEXT_DIM)
        self._traf.tag_configure("atk",  foreground=WARN)

        af, ai = self._card(right, "IDS ALERTS", HEAD, expand_h=True)
        self._alert = tk.Text(ai, bg=BG2, fg=WARN, font=MONOS, state=tk.DISABLED,
                               wrap=tk.WORD, bd=0)
        self._alert.pack(fill=tk.BOTH, expand=True)
        self._alert.tag_configure("red",  foreground=DANGER)
        self._alert.tag_configure("warn", foreground=WARN)
        self._alert.tag_configure("dim",  foreground=TEXT_DIM)

    def _card(self, parent, title, hfont, expand_h=True, height=None):
        f = tk.Frame(parent, bg=BG3, highlightbackground=MUTED2, highlightthickness=1)
        if expand_h:
            f.pack(fill=tk.BOTH, expand=True, pady=(0,6))
        else:
            f.pack(fill=tk.X, pady=(0,6))
            if height: f.configure(height=height)
        tk.Label(f, text=title, bg=BG3, fg=ACCENT, font=hfont,
                 anchor='w').pack(fill=tk.X, padx=10, pady=(6,2))
        tk.Frame(f, bg=MUTED2, height=1).pack(fill=tk.X, padx=8)
        inner = tk.Frame(f, bg=BG3)
        inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        return f, inner

    def _mk_node_panel(self, parent, HEAD, MONO, MONOB):
        _, inner = self._card(parent, "NODE STATUS", HEAD, expand_h=False)
        self._node_dot = {}
        self._node_lbl = {}
        self._node_bar = {}
        for nid in [1,2,3,4]:
            row = tk.Frame(inner, bg=BG3)
            row.pack(fill=tk.X, pady=3)
            dot = tk.Label(row, text="◉", fg=TEXT_DIM, bg=BG3,
                           font=("Consolas",13))
            dot.pack(side=tk.LEFT)
            tk.Label(row, text=f"  Node {nid} — {NODE_NAME[nid]}",
                     fg=TEXT, bg=BG3, font=MONO).pack(side=tk.LEFT)
            lbl = tk.Label(row, text="0 msgs", fg=TEXT_DIM, bg=BG3, font=MONO)
            lbl.pack(side=tk.RIGHT)
            self._node_dot[nid] = dot
            self._node_lbl[nid] = lbl
            # mini activity bar
            bar = tk.Canvas(inner, bg=BG2, height=3, highlightthickness=0)
            bar.pack(fill=tk.X, pady=(0,2))
            self._node_bar[nid] = bar

    def _mk_ids_panel(self, parent, HEAD, MONO, MONOS):
        _, inner = self._card(parent, "IDS METRICS", HEAD, expand_h=True)
        sm = ("Consolas", 9)

        tk.Label(inner, text="Anomaly Score", fg=TEXT_DIM, bg=BG3,
                 font=sm, anchor='w').pack(fill=tk.X)
        self._score_c = tk.Canvas(inner, bg=BG2, height=22, highlightthickness=0)
        self._score_c.pack(fill=tk.X, pady=(0,8))

        tk.Label(inner, text="Threat Level", fg=TEXT_DIM, bg=BG3,
                 font=sm, anchor='w').pack(fill=tk.X)
        self._lbl_threat = tk.Label(inner, text="CLEAN", fg=ACCENT2, bg=BG3,
                                     font=("Consolas",12,"bold"))
        self._lbl_threat.pack(anchor='w', pady=(0,8))

        tk.Label(inner, text="Bus Load", fg=TEXT_DIM, bg=BG3,
                 font=sm, anchor='w').pack(fill=tk.X)
        self._bus_c = tk.Canvas(inner, bg=BG2, height=22, highlightthickness=0)
        self._bus_c.pack(fill=tk.X, pady=(0,8))

        tk.Label(inner, text="Detection Log", fg=TEXT_DIM, bg=BG3,
                 font=sm, anchor='w').pack(fill=tk.X)
        self._det_txt = tk.Text(inner, bg=BG2, fg=TEXT_DIM, font=sm,
                                 state=tk.DISABLED, wrap=tk.WORD, height=8, bd=0)
        self._det_txt.pack(fill=tk.BOTH, expand=True)
        self._det_txt.tag_configure("hit", foreground=DANGER)
        self._det_txt.tag_configure("ok",  foreground=ACCENT2)

    # ─── Simulation subprocess ────────────────────────────────────────────────

    def _start_sim(self):
        if not os.path.exists(self.exe):
            self._push_alert(f"ERROR: {self.exe} not found", "red")
            return
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            p = subprocess.Popen([self.exe], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in p.stdout:
                self.event_q.put(line)
            p.wait()
        except Exception as e:
            self.event_q.put(f"[SIM_ERROR] {e}\n")
        self.event_q.put("__DONE__\n")

    # ─── Event processing (drains queue, paces by TICK) ──────────────────────

    def _drain_queue(self):
        try:
            for _ in range(200):
                line = self.event_q.get_nowait()
                if line.strip() == "__DONE__":
                    self.sim_done = True
                    self._lbl_time.config(text=f"T: {self.sim_time:.1f} ms  ■ DONE")
                    break

                # TICK line — advance sim time and flush pending display
                if line.startswith("[TICK]"):
                    m = re.search(r't=(\d+)', line)
                    if m:
                        self.sim_time = float(m.group(1))
                        self._lbl_time.config(
                            text=f"T: {self.sim_time:.0f} ms  ▶")
                    self._flush_pending()
                    break   # pace: process one tick per drain cycle

                parsed = parse_line(line)
                if parsed:
                    self.pending_events.append(parsed)
        except queue.Empty:
            pass
        self.after(self.TICK_DELAY, self._drain_queue)

    def _flush_pending(self):
        for (src, ev, det, ts) in self.pending_events:
            self._handle(src, ev, det, ts)
        self.pending_events.clear()

    def _handle(self, src, ev, det, ts):
        t = to_ms(ts)

        if src == "NETWORK" and ev == "MSG_TX":
            sid  = int(det.get("from", -1))
            mal  = det.get("MALICIOUS") == "1"
            mtyp = det.get("type", "?")
            self.node_msgs[sid] += 1
            self.node_last_t[sid] = self.sim_time
            self.bus_load = min(30, self.bus_load + 1)
            self._spawn_packet(sid, mal)
            self._log_traffic(t, sid, mtyp, mal)

        elif src == "SCHEDULER":
            if ev == "TASK_START":
                tid = self._task_id(det.get("task",""))
                if tid:
                    self.running_task = tid
                    self.task_start[tid] = t
            elif ev == "TASK_DONE":
                tid = self._task_id(det.get("task",""))
                if tid and tid in self.task_start:
                    self.task_blocks[tid].append((self.task_start[tid], t))
                    self.running_task = 0
            elif ev == "SAFE_MODE_ESCALATE":
                self.safe_level = det.get("level","GUARDED")
                self._update_safe_display()
            elif ev == "RECOVERED":
                self.safe_level = "NORMAL"
                self._update_safe_display()
            elif ev == "DEADLINE_MISS":
                self._push_det(f"MISS {det.get('task','')} @ {ts}", "hit")

        elif src == "IDS":
            score = det.get("score","0")
            try: self.anomaly_score = int(score)
            except: pass
            if ev == "ATTACK_CONFIRMED":
                self.threat_level = 2
                rsn = det.get("reasons", "")
                self._push_alert(
                    f"ATTACK @ {ts}\nSender={det.get('sender','?')} Score={score}\n{rsn}", "red")
                self.attack_marks.append((t, "ATTACK"))
                self._push_det(f"CONFIRMED sender={det.get('sender','?')} score={score}", "hit")
            elif ev == "SUSPECT_DETECTED":
                self.threat_level = 1
                self._push_alert(f"SUSPECT @ {ts} — {det.get('reasons','')}", "warn")
                self.attack_marks.append((t, "SUSPECT"))
                self._push_det(f"SUSPECT score={score}", "hit")

        elif src == "ATTACK":
            self._push_alert(f"{ev} @ {ts}", "warn")
            self._push_det(f"INJECT {ev} @ {ts}", "hit")

        elif src == "NODE" and ev == "INIT":
            nid = int(det.get("id", 0))
            role = det.get("role","?")
            self._push_det(f"Node {nid} ({role}) online", "ok")

    # ─── Animation loop ───────────────────────────────────────────────────────

    def _animate(self):
        self._update_node_dots()
        self._update_ids_metrics()
        self._draw_topo()
        self._draw_timeline()
        self._tick_packets()
        self.after(50, self._animate)

    def _tick_packets(self):
        alive = []
        for p in self.packets:
            p["prog"] += p["speed"]
            if p["prog"] < 1.0:
                alive.append(p)
        self.packets = alive

    def _update_safe_display(self):
        col = SAFE_COL.get(self.safe_level, ACCENT2)
        sym = {"NORMAL":"●","GUARDED":"◆","EMERGENCY":"⬟"}.get(self.safe_level,"●")
        self._lbl_safe.config(text=f"{sym} {self.safe_level}", fg=col)

    def _update_node_dots(self):
        for nid in [1,2,3,4]:
            age = self.sim_time - self.node_last_t[nid]
            active = age < 15
            col = NODE_COL[nid] if active else TEXT_DIM
            self._node_dot[nid].config(fg=col)
            self._node_lbl[nid].config(text=f"{self.node_msgs[nid]} msgs")
            # activity bar
            bar = self._node_bar[nid]
            bar.delete("all")
            w = bar.winfo_width() or 260
            ratio = min(1.0, max(0.0, 1.0 - age/20.0)) if active else 0
            if ratio > 0:
                bar.create_rectangle(0,0,int(w*ratio),3, fill=col, outline="")

    def _update_ids_metrics(self):
        # Score bar
        c = self._score_c
        w = c.winfo_width() or 260
        c.delete("all")
        r = min(1.0, self.anomaly_score/120.0)
        col = ACCENT2 if r<0.5 else WARN if r<0.83 else DANGER
        c.create_rectangle(0,0,int(w*r),22, fill=col, outline="")
        c.create_text(w//2, 11, text=str(self.anomaly_score),
                      fill=BG, font=("Consolas",9,"bold"))

        tname = {0:"CLEAN",1:"SUSPECT",2:"ATTACK"}.get(self.threat_level,"CLEAN")
        tcol  = {0:ACCENT2, 1:WARN, 2:DANGER}.get(self.threat_level, ACCENT2)
        self._lbl_threat.config(text=tname, fg=tcol)

        bc = self._bus_c
        bw = bc.winfo_width() or 260
        bc.delete("all")
        br = min(1.0, self.bus_load/30.0)
        bcol = ACCENT2 if br<0.5 else WARN if br<0.8 else DANGER
        bc.create_rectangle(0,0,int(bw*br),22, fill=bcol, outline="")
        bc.create_text(bw//2, 11, text=f"{self.bus_load}/30",
                       fill=BG, font=("Consolas",9,"bold"))
        # decay bus load
        if self.bus_load > 0:
            self.bus_load = max(0, self.bus_load - 1)
        # decay anomaly score
        if self.anomaly_score > 0 and self.threat_level == 0:
            self.anomaly_score = max(0, self.anomaly_score - 1)

    # ─── Topology canvas ──────────────────────────────────────────────────────

    def _draw_topo(self):
        c = self._topo
        c.delete("all")
        W = c.winfo_width() or 740
        H = c.winfo_height() or 260
        by = H * BUS_Y_RATIO

        # Bus
        c.create_line(W*0.06, by, W*0.94, by, fill=MUTED2, width=3, dash=(8,4))
        c.create_text(W*0.5, by-14, text="SHARED NETWORK BUS  (CAN/UART)",
                      fill=TEXT_DIM, font=("Consolas",8))

        # Compute node pixel positions
        pos = {}
        for nid in [1,2,3,4]:
            rx, ry = NODE_POS[nid]
            pos[nid] = (int(W*rx), int(H*ry))

        # Draw packets
        for pk in self.packets:
            sid = pk["src"]
            if sid not in pos: continue
            sx, sy = pos[sid]
            # travel from node down to bus
            px = sx
            py = sy + 24 + int((by - sy - 24) * pk["prog"])
            r  = 6
            c.create_oval(px-r, py-r, px+r, py+r,
                          fill=pk["col"], outline="", tags="pkt")
            # fading trail
            if pk["prog"] > 0.1:
                trail_y = py - 12
                c.create_line(px, py, px, trail_y,
                              fill=pk["col"], width=2,
                              tags="pkt")

        # Draw nodes
        for nid in [1,2,3,4]:
            x, y = pos[nid]
            col = NODE_COL[nid]
            age = self.sim_time - self.node_last_t[nid]

            # Connection to bus
            c.create_line(x, y+24, x, by, fill=MUTED2, width=1, dash=(3,3))

            # Glow ring (fades with age)
            glow = max(0.0, 1.0 - age/20.0)
            if glow > 0.05:
                gr = 26 + int(glow * 16)
                alpha_col = col  # tkinter can't do alpha, use outline trick
                for i in range(3):
                    rr = gr + i*4
                    c.create_oval(x-rr, y-rr, x+rr, y+rr,
                                  outline=col, width=1 if i>0 else 2, fill="")

            # Node body
            c.create_oval(x-24, y-24, x+24, y+24,
                          fill=BG3, outline=col, width=2)
            c.create_text(x, y, text=str(nid), fill=col,
                          font=("Consolas",13,"bold"))
            c.create_text(x, y+34, text=NODE_NAME[nid],
                          fill=TEXT_DIM, font=("Consolas",8))
            # Message count badge
            if self.node_msgs[nid] > 0:
                c.create_text(x+18, y-18,
                              text=str(self.node_msgs[nid]),
                              fill=col, font=("Consolas",7,"bold"))

        # Attack markers on bus
        sim_end = max(300.0, self.sim_time)
        for t_ms, kind in self.attack_marks:
            ax = W*0.06 + (W*0.88)*(t_ms/sim_end)
            col2 = DANGER if kind=="ATTACK" else WARN
            c.create_oval(ax-7,by-7,ax+7,by+7, fill=col2, outline="")
            c.create_text(ax, by-20, text=kind[:3], fill=col2,
                          font=("Consolas",7,"bold"))

        # Safe mode overlay
        if self.safe_level != "NORMAL":
            col2 = WARN if self.safe_level=="GUARDED" else DANGER
            c.create_text(W*0.5, H*0.92,
                          text=f"⚠  SYSTEM {self.safe_level}",
                          fill=col2, font=("Consolas",11,"bold"))

    # ─── Timeline canvas ──────────────────────────────────────────────────────

    def _draw_timeline(self):
        c = self._timeline
        c.delete("all")
        W = c.winfo_width() or 740
        H = c.winfo_height() or 155

        sim_end = max(300.0, self.sim_time)
        LBL_W = 110
        row_h = (H - 24) / 4

        for i, tid in enumerate([1,2,3,4]):
            y   = 4 + i*row_h
            col = TASK_COL[tid]
            # label
            c.create_text(LBL_W-6, y+row_h/2, text=TASK_NAME[tid],
                          fill=col, font=("Consolas",8), anchor='e')
            # track
            c.create_rectangle(LBL_W, y, W-4, y+row_h-2,
                               fill=BG, outline=MUTED2)
            # execution blocks
            for (s,e) in self.task_blocks[tid]:
                x1 = LBL_W + (s/sim_end)*(W-LBL_W-4)
                x2 = LBL_W + (e/sim_end)*(W-LBL_W-4)
                x2 = max(x2, x1+3)
                c.create_rectangle(x1, y+2, x2, y+row_h-4,
                                   fill=col, outline="")

        # Time axis
        c.create_line(LBL_W, H-18, W-4, H-18, fill=MUTED2)
        for ms in range(0, int(sim_end)+1, 50):
            x = LBL_W + (ms/sim_end)*(W-LBL_W-4)
            c.create_line(x, H-22, x, H-14, fill=MUTED2)
            c.create_text(x, H-8, text=str(ms), fill=TEXT_DIM,
                          font=("Consolas",7))

        # Attack markers
        for t_ms, kind in self.attack_marks:
            x = LBL_W + (t_ms/sim_end)*(W-LBL_W-4)
            col2 = DANGER if kind=="ATTACK" else WARN
            c.create_line(x, 4, x, H-20, fill=col2, width=1, dash=(4,2))

        # Cursor
        if self.sim_time > 0:
            cx = LBL_W + (self.sim_time/sim_end)*(W-LBL_W-4)
            c.create_line(cx, 4, cx, H-20, fill=ACCENT, width=2)

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _spawn_packet(self, src, malicious):
        col = DANGER if malicious else NODE_COL.get(src, ACCENT)
        self.packets.append({
            "src":src, "prog":0.0,
            "col":col, "speed": 0.08 + random.uniform(0,0.04)
        })

    def _task_id(self, name):
        for k,v in TASK_NAME.items():
            if v == name: return k
        return 0

    def _log_traffic(self, t, sid, mtyp, mal):
        txt = self._traf
        txt.config(state=tk.NORMAL)
        tag = "mal" if mal else "ok"
        pfx = "⚠" if mal else "·"
        txt.insert(tk.END, f"{pfx} {t:6.1f}ms  N{sid} {mtyp}\n", tag)
        if int(txt.index(tk.END).split('.')[0]) > 300:
            txt.delete("1.0","50.0")
        txt.see(tk.END)
        txt.config(state=tk.DISABLED)

    def _push_alert(self, msg, tag="warn"):
        self.alert_count += 1
        txt = self._alert
        txt.config(state=tk.NORMAL)
        txt.insert(tk.END, msg+"\n", tag)
        txt.insert(tk.END, "─"*40+"\n", "dim")
        txt.see(tk.END)
        txt.config(state=tk.DISABLED)

    def _push_det(self, msg, tag="ok"):
        txt = self._det_txt
        txt.config(state=tk.NORMAL)
        txt.insert(tk.END, msg+"\n", tag)
        if int(txt.index(tk.END).split('.')[0]) > 100:
            txt.delete("1.0","20.0")
        txt.see(tk.END)
        txt.config(state=tk.DISABLED)

# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv)>1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "simulation.exe")
    Dashboard(exe).mainloop()

"""
RT-ENSS Dashboard v4
- Reads all sim output into a buffer first
- Then replays it at controlled speed using tkinter's after() scheduler
- This guarantees smooth animation regardless of how fast the exe runs
"""
import tkinter as tk
from tkinter import font as tkfont
import subprocess, threading, queue, sys, re, os, random
from collections import defaultdict

BG      = "#0a0e1a"
BG2     = "#0d1220"
BG3     = "#111827"
ACCENT  = "#00d4ff"
ACCENT2 = "#00ff9f"
WARN    = "#ffb700"
DANGER  = "#ff3355"
MUTED2  = "#2a3a5a"
TEXT    = "#c8d8f0"
DIMTXT  = "#4a5a7a"

NODE_COL  = {1:"#00d4ff", 2:"#00ff9f", 3:"#ffb700", 4:"#b388ff"}
NODE_NAME = {1:"Sensor",  2:"Control", 3:"Actuator", 4:"Gateway"}
TASK_COL  = {1:"#00d4ff", 2:"#00ff9f", 3:"#ffb700", 4:"#b388ff"}
TASK_NAME = {1:"SensorPoll",2:"ControlLoop",3:"ActuatorCheck",4:"GatewayDiag"}
SAFE_COL  = {"NORMAL":ACCENT2,"GUARDED":WARN,"EMERGENCY":DANGER}
NODE_POS  = {1:(0.18,0.32), 2:(0.50,0.32), 3:(0.82,0.32), 4:(0.50,0.72)}
BUS_Y     = 0.57

EVENT_RE = re.compile(
    r'\[(\w+)\]\s+(\w+)(?:\s+\|\s+(.+?))?\s+\|\s+([\d.e+\-]+\s+\w+)')

def parse_line(line):
    m = EVENT_RE.match(line.strip())
    if not m: return None
    src, ev, det_raw, ts = m.groups()
    det = {}
    if det_raw:
        for p in det_raw.split():
            if '=' in p: k,v=p.split('=',1); det[k]=v
            else: det[p]=True
    return src, ev, det, ts

def to_ms(ts):
    try:
        v,u = ts.strip().split(); v=float(v)
        return v*1000 if u=='s' else v if u=='ms' else v/1000
    except: return 0.0


class Dashboard(tk.Tk):
    # How many ms of real time each simulated tick takes in the replay
    MS_PER_TICK = 100  # 300 ticks x 100ms = 30 seconds total

    def __init__(self, exe):
        super().__init__()
        self.exe = exe
        self.title("RT-ENSS Dashboard — Real-Time Embedded Network Security Simulator")
        self.configure(bg=BG)
        self.geometry("1400x860")
        self.minsize(1100, 700)

        # Replay buffer: list of (tick_number, [events_at_this_tick])
        self.replay_buffer = []   # filled by background thread
        self.current_tick  = 0
        self.collecting    = True  # True while sim is still running

        # Live display state
        self.sim_time    = 0.0
        self.safe_level  = "NORMAL"
        self.anomaly     = 0
        self.threat      = 0
        self.bus_load    = 0
        self.node_msgs   = defaultdict(int)
        self.node_last   = defaultdict(lambda: -999.0)
        self.task_blocks = defaultdict(list)
        self.task_start  = {}
        self.atk_marks   = []
        self.packets     = []

        self._build_ui()
        self._show_loading()
        threading.Thread(target=self._collect_sim, daemon=True).start()
        self.after(200, self._check_ready)
        self.after(50,  self._animate)

    # Collect sim output into replay buffer 
    def _collect_sim(self):
        """Run sim, bucket all events by tick number."""
        try:
            p = subprocess.Popen(
                [self.exe],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1)
            current_tick = 0
            bucket = []
            for line in p.stdout:
                line = line.rstrip()
                if not line: continue
                if line.startswith("[TICK]"):
                    m = re.search(r't=(\d+)', line)
                    t = int(m.group(1)) if m else current_tick+1
                    self.replay_buffer.append((t, bucket))
                    bucket = []
                    current_tick = t
                elif "[SIM_DONE]" in line:
                    break
                else:
                    parsed = parse_line(line)
                    if parsed:
                        bucket.append(parsed)
            if bucket:
                self.replay_buffer.append((current_tick+1, bucket))
            p.wait()
        except Exception as e:
            self.replay_buffer.append((-1, []))
        finally:
            self.collecting = False

    def _check_ready(self):
        """Wait until we have at least a few ticks buffered, then start replay."""
        if not self.collecting and len(self.replay_buffer) == 0:
            self._show_error("Simulation produced no output. Check simulation.exe.")
            return
        # Start replaying once we have 5+ ticks buffered, or sim is done
        if len(self.replay_buffer) >= 5 or not self.collecting:
            self._lbl_time.config(text="T: 0 ms  ▶ RUNNING")
            self._topo_status = "running"
            self.after(self.MS_PER_TICK, self._replay_tick)
        else:
            dots = "." * ((len(self.replay_buffer) % 4) + 1)
            self._lbl_time.config(
                text=f"Buffering simulation output{dots}  "
                     f"({len(self.replay_buffer)} ticks ready)")
            self.after(200, self._check_ready)

    def _replay_tick(self):
        """Process one tick from the replay buffer, then schedule next."""
        if self.current_tick >= len(self.replay_buffer):
            if self.collecting:
                # Sim still running but we caught up — wait
                self.after(50, self._replay_tick)
            else:
                # Done
                self._lbl_time.config(
                    text=f"T: {self.sim_time:.0f} ms  DONE")
                self._topo_status = "done"
            return

        tick_num, events = self.replay_buffer[self.current_tick]
        self.sim_time = float(tick_num)
        self._lbl_time.config(text=f"T: {self.sim_time:.0f} ms  ▶ RUNNING")

        for ev in events:
            self._handle(*ev)

        self.current_tick += 1
        self.after(self.MS_PER_TICK, self._replay_tick)

    # Handle events 
    def _handle(self, src, ev, det, ts):
        t = to_ms(ts)
        if src == "NETWORK" and ev == "MSG_TX":
            sid  = int(det.get("from", -1))
            mal  = det.get("MALICIOUS") == "1"
            mtyp = det.get("type", "?")
            self.node_msgs[sid] += 1
            self.node_last[sid]  = self.sim_time
            self.bus_load = min(30, self.bus_load + 2)
            self._spawn_pkt(sid, mal)
            self._log_traffic(t, sid, mtyp, mal)

        elif src == "SCHEDULER":
            if ev == "TASK_START":
                tid = self._tid(det.get("task",""))
                if tid: self.task_start[tid] = t
            elif ev == "TASK_DONE":
                tid = self._tid(det.get("task",""))
                if tid and tid in self.task_start:
                    self.task_blocks[tid].append((self.task_start[tid], t))
            elif ev == "SAFE_MODE_ESCALATE":
                self.safe_level = det.get("level","GUARDED")
                self._upd_safe()
            elif ev == "RECOVERED":
                self.safe_level = "NORMAL"
                self._upd_safe()
            elif ev == "DEADLINE_MISS":
                self._evlog(f"DEADLINE MISS: {det.get('task','')}", "hit")

        elif src == "IDS":
            sc = det.get("score","0")
            try: self.anomaly = int(sc)
            except: pass
            if ev == "ATTACK_CONFIRMED":
                self.threat = 2
                self.atk_marks.append((t, "ATTACK"))
                self._alert(f"ATTACK @ {ts}\nSender={det.get('sender','?')} Score={sc}", "red")
                self._evlog(f"ATTACK CONFIRMED score={sc}", "hit")
            elif ev == "SUSPECT_DETECTED":
                self.threat = 1
                self.atk_marks.append((t, "SUSPECT"))
                self._alert(f"SUSPECT @ {ts}", "warn")
                self._evlog(f"SUSPECT score={sc}", "hit")

        elif src == "ATTACK":
            self._alert(f"{ev} @ {ts}", "warn")
            self._evlog(f"INJECTED: {ev}", "hit")

        elif src == "NODE" and ev == "INIT":
            self._evlog(f"Node {det.get('id','?')} ({det.get('role','?')}) online", "ok")

    # Animation loop 
    def _animate(self):
        self._upd_nodes()
        self._upd_ids()
        self._draw_topo()
        self._draw_tl()
        self.packets = [p for p in self.packets if self._tick_pkt(p)]
        if self.bus_load > 0: self.bus_load = max(0, self.bus_load - 1)
        if self.anomaly > 0 and self.threat == 0:
            self.anomaly = max(0, self.anomaly - 1)
        self.after(50, self._animate)

    def _tick_pkt(self, p):
        p["prog"] += p["spd"]
        return p["prog"] < 1.0

    # Build UI 
    def _build_ui(self):
        M  = ("Consolas", 10)
        MS = ("Consolas", 9)
        MB = ("Consolas", 11, "bold")
        H  = ("Consolas", 10, "bold")
        T  = ("Consolas", 14, "bold")

        hdr = tk.Frame(self, bg="#0c1420", height=48)
        hdr.pack(fill=tk.X); hdr.pack_propagate(False)
        tk.Label(hdr, text="RT-ENSS  SECURITY DASHBOARD",
                 bg="#0c1420", fg=ACCENT, font=T).pack(side=tk.LEFT, padx=16, pady=10)
        self._lbl_safe = tk.Label(hdr, text="● NORMAL", bg="#0c1420",
                                   fg=ACCENT2, font=MB)
        self._lbl_safe.pack(side=tk.RIGHT, padx=20, pady=10)
        self._lbl_time = tk.Label(hdr, text="Collecting simulation output...",
                                   bg="#0c1420", fg=TEXT, font=M)
        self._lbl_time.pack(side=tk.RIGHT, padx=4, pady=10)

        body = tk.Frame(self, bg=BG); body.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=BG, width=300)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(8,4), pady=8)
        left.pack_propagate(False)

        mid = tk.Frame(body, bg=BG)
        mid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=8)

        right = tk.Frame(body, bg=BG, width=360)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(4,8), pady=8)
        right.pack_propagate(False)

        self._mk_nodes(left, H, M)
        self._mk_ids(left, H, MS)
        self._mk_topo(mid, H)
        self._mk_timeline(mid, H)
        self._mk_traffic(right, H, MS)
        self._mk_alerts(right, H, MS)
        self._topo_status = "loading"

    def _card(self, parent, title, hf, expand=True, h=None):
        f = tk.Frame(parent, bg=BG3, highlightbackground=MUTED2, highlightthickness=1)
        if expand: f.pack(fill=tk.BOTH, expand=True, pady=(0,6))
        else:
            f.pack(fill=tk.X, pady=(0,6))
            if h: f.configure(height=h)
        tk.Label(f, text=title, bg=BG3, fg=ACCENT, font=hf,
                 anchor='w').pack(fill=tk.X, padx=10, pady=(6,2))
        tk.Frame(f, bg=MUTED2, height=1).pack(fill=tk.X, padx=8)
        inn = tk.Frame(f, bg=BG3)
        inn.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        return inn

    def _mk_nodes(self, p, H, M):
        inn = self._card(p, "NODE STATUS", H, expand=False)
        self._ndot={}; self._nlbl={}; self._nbar={}
        for nid in [1,2,3,4]:
            row = tk.Frame(inn, bg=BG3); row.pack(fill=tk.X, pady=3)
            dot = tk.Label(row, text="◉", fg=DIMTXT, bg=BG3, font=("Consolas",13))
            dot.pack(side=tk.LEFT)
            tk.Label(row, text=f"  Node {nid} — {NODE_NAME[nid]}",
                     fg=TEXT, bg=BG3, font=M).pack(side=tk.LEFT)
            lbl = tk.Label(row, text="0 msgs", fg=DIMTXT, bg=BG3, font=M)
            lbl.pack(side=tk.RIGHT)
            self._ndot[nid]=dot; self._nlbl[nid]=lbl
            bar = tk.Canvas(inn, bg=BG2, height=3, highlightthickness=0)
            bar.pack(fill=tk.X, pady=(0,2))
            self._nbar[nid]=bar

    def _mk_ids(self, p, H, MS):
        inn = self._card(p, "IDS METRICS", H, expand=True)
        sm = ("Consolas",9)
        tk.Label(inn,text="Anomaly Score",fg=DIMTXT,bg=BG3,font=sm,anchor='w').pack(fill=tk.X)
        self._sc=tk.Canvas(inn,bg=BG2,height=22,highlightthickness=0)
        self._sc.pack(fill=tk.X,pady=(0,8))
        tk.Label(inn,text="Threat Level",fg=DIMTXT,bg=BG3,font=sm,anchor='w').pack(fill=tk.X)
        self._lthreat=tk.Label(inn,text="CLEAN",fg=ACCENT2,bg=BG3,font=("Consolas",12,"bold"))
        self._lthreat.pack(anchor='w',pady=(0,8))
        tk.Label(inn,text="Bus Load",fg=DIMTXT,bg=BG3,font=sm,anchor='w').pack(fill=tk.X)
        self._bc=tk.Canvas(inn,bg=BG2,height=22,highlightthickness=0)
        self._bc.pack(fill=tk.X,pady=(0,8))
        tk.Label(inn,text="Event Log",fg=DIMTXT,bg=BG3,font=sm,anchor='w').pack(fill=tk.X)
        self._evtxt=tk.Text(inn,bg=BG2,fg=DIMTXT,font=sm,state=tk.DISABLED,
                             wrap=tk.WORD,height=8,bd=0)
        self._evtxt.pack(fill=tk.BOTH,expand=True)
        self._evtxt.tag_configure("hit",foreground=DANGER)
        self._evtxt.tag_configure("ok", foreground=ACCENT2)

    def _mk_topo(self, p, H):
        inn = self._card(p,"NETWORK TOPOLOGY",H,expand=True)
        self._topo=tk.Canvas(inn,bg=BG2,highlightthickness=0)
        self._topo.pack(fill=tk.BOTH,expand=True)
        self._topo.bind("<Configure>",lambda e:self._draw_topo())

    def _mk_timeline(self, p, H):
        inn = self._card(p,"SCHEDULER TIMELINE  (RMS)",H,expand=False,h=190)
        self._tl=tk.Canvas(inn,bg=BG2,highlightthickness=0,height=165)
        self._tl.pack(fill=tk.BOTH,expand=True)

    def _mk_traffic(self, p, H, MS):
        inn = self._card(p,"TRAFFIC LOG",H,expand=True)
        self._traf=tk.Text(inn,bg=BG2,fg=TEXT,font=MS,state=tk.DISABLED,wrap=tk.NONE,bd=0)
        self._traf.pack(fill=tk.BOTH,expand=True)
        self._traf.tag_configure("mal",foreground=DANGER)
        self._traf.tag_configure("ok", foreground=DIMTXT)

    def _mk_alerts(self, p, H, MS):
        inn = self._card(p,"IDS ALERTS",H,expand=True)
        self._alrt=tk.Text(inn,bg=BG2,fg=WARN,font=MS,state=tk.DISABLED,wrap=tk.WORD,bd=0)
        self._alrt.pack(fill=tk.BOTH,expand=True)
        self._alrt.tag_configure("red", foreground=DANGER)
        self._alrt.tag_configure("warn",foreground=WARN)
        self._alrt.tag_configure("dim", foreground=DIMTXT)

    def _show_loading(self):
        pass  # lbl_time already shows "Collecting..."

    def _show_error(self, msg):
        self._lbl_time.config(text="ERROR", fg=DANGER)
        self._alert(msg, "red")

    # Drawing 
    def _upd_safe(self):
        col = SAFE_COL.get(self.safe_level, ACCENT2)
        sym = {"NORMAL":"●","GUARDED":"◆","EMERGENCY":"⬟"}.get(self.safe_level,"●")
        self._lbl_safe.config(text=f"{sym} {self.safe_level}", fg=col)

    def _upd_nodes(self):
        for nid in [1,2,3,4]:
            age = self.sim_time - self.node_last[nid]
            act = age < 15
            col = NODE_COL[nid] if act else DIMTXT
            self._ndot[nid].config(fg=col)
            self._nlbl[nid].config(text=f"{self.node_msgs[nid]} msgs")
            bar=self._nbar[nid]; bar.delete("all")
            w=bar.winfo_width() or 260
            r=max(0.0,1.0-age/15.0) if act else 0.0
            if r>0: bar.create_rectangle(0,0,int(w*r),3,fill=col,outline="")

    def _upd_ids(self):
        c=self._sc; w=c.winfo_width() or 260; c.delete("all")
        r=min(1.0,self.anomaly/120.0)
        col=ACCENT2 if r<0.5 else WARN if r<0.83 else DANGER
        c.create_rectangle(0,0,int(w*r),22,fill=col,outline="")
        c.create_text(w//2,11,text=str(self.anomaly),fill=BG,font=("Consolas",9,"bold"))
        tn={0:"CLEAN",1:"SUSPECT",2:"ATTACK"}.get(self.threat,"CLEAN")
        tc={0:ACCENT2,1:WARN,2:DANGER}.get(self.threat,ACCENT2)
        self._lthreat.config(text=tn,fg=tc)
        bc=self._bc; bw=bc.winfo_width() or 260; bc.delete("all")
        br=min(1.0,self.bus_load/30.0)
        bcol=ACCENT2 if br<0.5 else WARN if br<0.8 else DANGER
        bc.create_rectangle(0,0,int(bw*br),22,fill=bcol,outline="")
        bc.create_text(bw//2,11,text=f"{self.bus_load}/30",fill=BG,font=("Consolas",9,"bold"))

    def _draw_topo(self):
        c=self._topo; c.delete("all")
        W=c.winfo_width() or 740; H=c.winfo_height() or 280
        by=int(H*BUS_Y)

        if self._topo_status == "loading":
            c.create_text(W//2,H//2-16,
                text="Collecting simulation output...",
                fill=ACCENT,font=("Consolas",12,"bold"))
            pct=min(100,int(len(self.replay_buffer)/3))
            bw=int(W*0.6); bx=(W-bw)//2
            c.create_rectangle(bx,H//2+10,bx+bw,H//2+28,outline=MUTED2,fill=BG2)
            c.create_rectangle(bx,H//2+10,bx+int(bw*pct/100),H//2+28,fill=ACCENT,outline="")
            c.create_text(W//2,H//2+19,text=f"{pct}%",fill=BG,font=("Consolas",9,"bold"))
            return

        c.create_line(W*0.05,by,W*0.95,by,fill=MUTED2,width=3,dash=(8,4))
        c.create_text(W*0.5,by-14,text="SHARED NETWORK BUS  (CAN/UART)",
                      fill=DIMTXT,font=("Consolas",8))
        pos={}
        for nid in [1,2,3,4]:
            rx,ry=NODE_POS[nid]; pos[nid]=(int(W*rx),int(H*ry))

        for pk in self.packets:
            sid=pk["src"]
            if sid not in pos: continue
            sx,sy=pos[sid]; px=sx
            py=sy+26+int((by-sy-26)*pk["prog"])
            c.create_oval(px-6,py-6,px+6,py+6,fill=pk["col"],outline="")
            if pk["prog"]>0.05:
                c.create_line(px,py,px,py-10,fill=pk["col"],width=2)

        for nid in [1,2,3,4]:
            x,y=pos[nid]; col=NODE_COL[nid]
            age=self.sim_time-self.node_last[nid]
            c.create_line(x,y+26,x,by,fill=MUTED2,width=1,dash=(3,3))
            glow=max(0.0,1.0-age/20.0)
            for i in range(3):
                if glow>0.05:
                    r=28+i*6+int(glow*10)
                    c.create_oval(x-r,y-r,x+r,y+r,outline=col,width=1,fill="")
            c.create_oval(x-26,y-26,x+26,y+26,fill=BG3,outline=col,width=2)
            c.create_text(x,y,text=str(nid),fill=col,font=("Consolas",14,"bold"))
            c.create_text(x,y+38,text=NODE_NAME[nid],fill=DIMTXT,font=("Consolas",8))
            if self.node_msgs[nid]>0:
                c.create_text(x+20,y-20,text=str(self.node_msgs[nid]),
                              fill=col,font=("Consolas",7,"bold"))

        se=max(300.0,self.sim_time)
        for tm,kind in self.atk_marks:
            ax=W*0.05+(W*0.90)*(tm/se)
            col2=DANGER if kind=="ATTACK" else WARN
            c.create_oval(ax-7,by-7,ax+7,by+7,fill=col2,outline="")
            c.create_text(ax,by-22,text=kind[:3],fill=col2,font=("Consolas",7,"bold"))

        if self.safe_level!="NORMAL":
            col2=WARN if self.safe_level=="GUARDED" else DANGER
            c.create_text(W*0.5,H*0.93,
                text=f"  SYSTEM {self.safe_level}  ",
                fill=col2,font=("Consolas",12,"bold"))

    def _draw_tl(self):
        c=self._tl; c.delete("all")
        W=c.winfo_width() or 740; H=c.winfo_height() or 165
        se=max(300.0,self.sim_time); LW=110; rh=(H-24)/4
        for i,tid in enumerate([1,2,3,4]):
            y=4+i*rh; col=TASK_COL[tid]
            c.create_text(LW-6,y+rh/2,text=TASK_NAME[tid],
                          fill=col,font=("Consolas",8),anchor='e')
            c.create_rectangle(LW,y,W-4,y+rh-2,fill=BG,outline=MUTED2)
            for (s,e) in self.task_blocks[tid]:
                x1=LW+(s/se)*(W-LW-4); x2=LW+(e/se)*(W-LW-4)
                x2=max(x2,x1+3)
                c.create_rectangle(x1,y+2,x2,y+rh-4,fill=col,outline="")
        c.create_line(LW,H-18,W-4,H-18,fill=MUTED2)
        for ms in range(0,int(se)+1,50):
            x=LW+(ms/se)*(W-LW-4)
            c.create_line(x,H-22,x,H-14,fill=MUTED2)
            c.create_text(x,H-8,text=str(ms),fill=DIMTXT,font=("Consolas",7))
        for tm,kind in self.atk_marks:
            x=LW+(tm/se)*(W-LW-4)
            c.create_line(x,4,x,H-20,fill=DANGER if kind=="ATTACK" else WARN,
                          width=1,dash=(4,2))
        if self.sim_time>0:
            cx=LW+(self.sim_time/se)*(W-LW-4)
            c.create_line(cx,4,cx,H-20,fill=ACCENT,width=2)

    # Helpers 
    def _spawn_pkt(self, src, mal):
        col=DANGER if mal else NODE_COL.get(src,ACCENT)
        self.packets.append({"src":src,"prog":0.0,"col":col,
                              "spd":0.07+random.uniform(0,0.03)})

    def _tid(self, name):
        for k,v in TASK_NAME.items():
            if v==name: return k
        return 0

    def _log_traffic(self, t, sid, mtyp, mal):
        tx=self._traf; tx.config(state=tk.NORMAL)
        tx.insert(tk.END,f"{'!' if mal else ' '} {t:6.1f}ms  N{sid} {mtyp}\n",
                  "mal" if mal else "ok")
        if int(tx.index(tk.END).split('.')[0])>300: tx.delete("1.0","50.0")
        tx.see(tk.END); tx.config(state=tk.DISABLED)

    def _alert(self, msg, tag="warn"):
        tx=self._alrt; tx.config(state=tk.NORMAL)
        tx.insert(tk.END,msg+"\n",tag)
        tx.insert(tk.END,"-"*38+"\n","dim")
        tx.see(tk.END); tx.config(state=tk.DISABLED)

    def _evlog(self, msg, tag="ok"):
        tx=self._evtxt; tx.config(state=tk.NORMAL)
        tx.insert(tk.END,msg+"\n",tag)
        if int(tx.index(tk.END).split('.')[0])>100: tx.delete("1.0","20.0")
        tx.see(tk.END); tx.config(state=tk.DISABLED)

if __name__=="__main__":
    exe=sys.argv[1] if len(sys.argv)>1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),"simulation.exe")
    Dashboard(exe).mainloop()
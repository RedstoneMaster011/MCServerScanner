import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import font as tkfont
import socket
import threading
import json
import time
from concurrent.futures import ThreadPoolExecutor
from mcstatus import JavaServer

# --- BOT LOGIC INTEGRATION ---
try:
    from javascript import require, On

    mineflayer = require("mineflayer")
    BOT_ENABLED = True
except:
    BOT_ENABLED = False


class UltimateMCScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("MC Server IP Scanner")
        self.root.geometry("1200x900")
        self.scanning = False
        self.found_servers = []
        self.last_ui_update = 0
        # Added 'access' to your existing sort and width trackers
        self.sort_reverse = {col: False for col in ("ip", "version", "software", "players", "ping", "access", "motd")}
        self.col_widths = {col: 50 for col in ("ip", "version", "software", "players", "ping", "access", "motd")}

        # --- FONT & STYLE ---
        self.tree_font = tkfont.Font(family="Arial", size=6)
        self.style = ttk.Style()
        self.style.configure("Treeview", font=self.tree_font, rowheight=14)
        self.style.configure("Treeview.Heading", font=('Arial', 8, 'bold'))

        # --- Settings Header ---
        header = tk.Frame(root)
        header.pack(pady=10, fill=tk.X, padx=10)

        tk.Label(header, text="Min Port:").grid(row=0, column=0, padx=5)
        self.port_min = tk.Entry(header, width=6)
        self.port_min.insert(0, "25565")
        self.port_min.grid(row=0, column=1, padx=5)

        tk.Label(header, text="Max Port:").grid(row=0, column=2, padx=5)
        self.port_max = tk.Entry(header, width=6)
        self.port_max.insert(0, "25565")
        self.port_max.grid(row=0, column=3, padx=5)

        tk.Label(header, text="Threads:").grid(row=0, column=4, padx=5)
        self.thread_entry = tk.Entry(header, width=6)
        self.thread_entry.insert(0, "800")
        self.thread_entry.grid(row=0, column=5, padx=5)

        # --- NEW: BOTTING CHECKBOX ---
        self.bot_var = tk.BooleanVar(value=False)
        self.bot_cb = tk.Checkbutton(header, text="TEST ACCESS (BOT) ᴺᵉᵉᵈˢ ᴺᵒᵈᵉᴶˢ", variable=self.bot_var, command=self.toggle_username_entry)
        self.bot_cb.grid(row=0, column=6, padx=10)

        tk.Label(header, text="Username:").grid(row=0, column=7)
        self.bot_user_entry = tk.Entry(header, width=12)
        self.bot_user_entry.insert(0, "ServerScanner")
        self.bot_user_entry.config(state="disabled")  # Disabled by default
        self.bot_user_entry.grid(row=0, column=8, padx=5)

        # IP Input
        tk.Label(root, text="IP Ranges:", font=('Arial', 9, 'bold')).pack()
        self.ip_input = tk.Text(root, height=4, width=100)
        self.ip_input.pack(pady=5)
        self.ip_input.insert("1.0", "51.254.0.0\n147.135.0.0")

        # Controls
        ctrl_frame = tk.Frame(root)
        ctrl_frame.pack(pady=10, fill=tk.X, padx=10)

        self.start_btn = tk.Button(ctrl_frame, text="NEW SCAN", command=self.toggle_scan, bg="#4CAF50", fg="white",
                                   font=('Arial', 9, 'bold'), width=14)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.update_btn = tk.Button(ctrl_frame, text="UPDATE", command=self.update_existing_list, bg="#FF9800",
                                    fg="white", font=('Arial', 9, 'bold'), width=14)
        self.update_btn.pack(side=tk.LEFT, padx=5)

        self.open_btn = tk.Button(ctrl_frame, text="OPEN LIST", command=self.open_file, bg="#9C27B0", fg="white",
                                  font=('Arial', 9, 'bold'), width=14)
        self.open_btn.pack(side=tk.LEFT, padx=5)

        self.save_btn = tk.Button(ctrl_frame, text="SAVE LIST", command=self.manual_save_as, bg="#2196F3",
                                  fg="white", font=('Arial', 9, 'bold'), width=14)
        self.save_btn.pack(side=tk.LEFT, padx=5)

        self.stats_label = tk.Label(root, text="Ready", font=('Arial', 10, 'bold'), fg="#555")
        self.stats_label.pack()

        # --- Table (Added "access" column) ---
        columns = ("ip", "version", "software", "players", "ping", "access", "motd")
        self.tree = ttk.Treeview(root, columns=columns, show='headings', style="Treeview")

        for col in columns:
            self.tree.heading(col, text=col.upper(), command=lambda _col=col: self.sort_by_column(_col))
            self.tree.column(col, anchor="w", width=self.col_widths[col])

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)

        self.tree.bind('<ButtonRelease-1>', self.copy_line)
        scrolly = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrolly.set)
        scrolly.pack(side=tk.RIGHT, fill=tk.Y, pady=10, padx=(0, 10))

    def toggle_username_entry(self):
        """Enables/Disables the username box based on the checkbox"""
        if self.bot_var.get():
            self.bot_user_entry.config(state="normal")
        else:
            self.bot_user_entry.config(state="disabled")

    def get_access_status(self, ip, port):
        if not BOT_ENABLED: return "N/A"

        # Pull username from UI
        current_username = self.bot_user_entry.get() or "ServerScanner"

        result = "checking..."
        done = threading.Event()

        def bot_thread():
            nonlocal result
            try:
                bot = mineflayer.createBot({
                    "host": ip,
                    "port": port,
                    "username": current_username,
                    "auth": "offline",
                    "hideErrors": True,
                    "connectTimeout": 2000
                })

                @On(bot, "login")
                def on_login(this):
                    nonlocal result
                    result = "OpenCracked"
                    bot.quit()
                    done.set()

                @On(bot, "kicked")
                def on_kick(this, reason, *args):
                    nonlocal result
                    r = str(reason).lower()
                    if any(x in r for x in ["session", "authentication", "not authenticated", "premium"]):
                        result = "OpenPremium"
                    elif any(x in r for x in ["whitelist", "not on the list"]):
                        result = "Whitelisted"
                    else:
                        result = "Whitelisted"
                    bot.quit()
                    done.set()

                @On(bot, "error")
                def on_err(this, err):
                    done.set()
            except:
                done.set()

        threading.Thread(target=bot_thread, daemon=True).start()
        done.wait(timeout=2.5)
        return result if result != "checking..." else "Whitelisted"

    def adjust_column_widths(self, server_data):
        for col in ("ip", "version", "software", "players", "ping", "access", "motd"):
            text_val = str(server_data[col])
            new_width = self.tree_font.measure(text_val) + 20
            if new_width > self.col_widths[col]:
                self.col_widths[col] = new_width
                self.tree.column(col, width=new_width)

    def sort_by_column(self, col):
        self.sort_reverse[col] = not self.sort_reverse[col]

        def sort_key(x):
            val = x[col]
            if col == "players": return int(val)
            if col == "ping": return int(val.replace('ms', '')) if 'ms' in val else 999
            return str(val).lower()

        self.found_servers.sort(key=sort_key, reverse=self.sort_reverse[col])
        self.update_display(force=True)

    def copy_line(self, event):
        selected = self.tree.focus()
        if selected:
            ip_val = self.tree.item(selected, "values")[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip_val)
            self.stats_label.config(text=f"COPIED: {ip_val}", fg="blue")

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("MC Server List", "*.mserli")])
        if path:
            with open(path, "r", encoding="utf-8") as f: self.found_servers = json.load(f)
            self.found_servers.sort(key=lambda x: x['players'], reverse=True)
            self.update_display(force=True)

    def manual_save_as(self):
        if not self.found_servers: return
        path = filedialog.asksaveasfilename(defaultextension=".mserli", filetypes=[("MC Server List", "*.mserli")])
        if path:
            with open(path, "w", encoding="utf-8") as f: json.dump(self.found_servers, f)
            messagebox.showinfo("Success", "Saved.")

    def update_existing_list(self):
        if not self.found_servers or self.scanning: return
        targets = [(s['ip'].split(':')[0], int(s['ip'].split(':')[1])) for s in self.found_servers]
        self.found_servers = []
        self.scanning = True
        self.start_btn.config(text="STOP", bg="red")
        threading.Thread(target=self.run_scanner, args=(targets,), daemon=True).start()

    def check_server(self, ip, port):
        if not self.scanning: return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.8)
                if s.connect_ex((ip, port)) == 0:
                    server = JavaServer.lookup(f"{ip}:{port}")
                    status = server.status()

                    # Perform Botting if checkbox is checked
                    access_val = "N/A"
                    if self.bot_var.get():
                        access_val = self.get_access_status(ip, port)

                    v = status.version.name.lower()
                    soft = "Vanilla / Modded"
                    for loader in ["paper", "spigot", "forge", "fabric", "bukkit"]:
                        if loader in v: soft = loader.capitalize()

                    return {"ip": f"{ip}:{port}", "version": status.version.name.split(" ")[-1], "software": soft,
                            "players": int(status.players.online), "ping": f"{round(status.latency)}ms",
                            "access": access_val, "motd": str(status.description)[:60].replace('\n', ' ')}
        except:
            pass
        return None

    def run_scanner(self, custom_targets=None):
        if custom_targets:
            targets = custom_targets
        else:
            raw = self.ip_input.get("1.0", tk.END).strip().split('\n')
            ports = range(int(self.port_min.get()), int(self.port_max.get()) + 1)
            targets = []
            for line in raw:
                line = line.strip()
                if not line: continue
                if line.endswith(".0.0"):
                    base = ".".join(line.split(".")[:2])
                    for b3 in range(256):
                        for b4 in range(256):
                            for p in ports: targets.append((f"{base}.{b3}.{b4}", p))
                elif line.endswith(".0"):
                    base = ".".join(line.split(".")[:3])
                    for i in range(1, 255):
                        for p in ports: targets.append((f"{base}.{i}", p))
                else:
                    for p in ports: targets.append((line, p))

        total = len(targets)
        thread_count = int(self.thread_entry.get() or 250)

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(self.check_server, t[0], t[1]) for t in targets]
            for i, future in enumerate(futures):
                if not self.scanning: break
                res = future.result()
                if res:
                    self.found_servers.append(res)
                    self.found_servers.sort(key=lambda x: x['players'], reverse=True)
                    self.update_display()
                if i % 500 == 0: self.root.after(0, self.update_stats, i, total)

        self.scanning = False
        self.root.after(0, self.update_display, True)
        self.root.after(0, self.scan_finished)

        if res:
            self.found_servers.append(res)
            # Force the UI to insert the row immediately
            self.root.after(0, self.instant_add_row, res)

    def instant_add_row(self, res):
        """Adds a row to the top of the list and refreshes the screen instantly"""
        self.tree.insert("", 0, values=(res['ip'], res['version'], res['software'],
                                        res['players'], res['ping'], res['access'], res['motd']))
        self.stats_label.config(text=f"Found: {len(self.found_servers)}")
        self.root.update_idletasks()  # This removes the 3-second 'lag' feel

    def update_stats(self, checked, total):
        self.stats_label.config(text=f"Checked: {checked} / {total} | Found: {len(self.found_servers)}")

    def update_display(self, force=False):
        current_time = time.time()
        if force or (current_time - self.last_ui_update > 2.0):
            self.last_ui_update = current_time
            for i in self.tree.get_children(): self.tree.delete(i)
            for s in self.found_servers[:300]:
                self.tree.insert("", tk.END,
                                 values=(s['ip'], s['version'], s['software'], s['players'], s['ping'], s['access'],
                                         s['motd']))

    def toggle_scan(self):
        if not self.scanning:
            self.found_servers = []
            self.scanning = True
            self.start_btn.config(text="STOP", bg="red")
            threading.Thread(target=self.run_scanner, daemon=True).start()
        else:
            self.scanning = False

    def scan_finished(self):
        self.start_btn.config(text="NEW SCAN", bg="#4CAF50")
        self.stats_label.config(text=f"Finished. Total Servers: {len(self.found_servers)}")


if __name__ == "__main__":
    messagebox.showinfo("MC Server IP Scanner", "To Use Bots, You Need NodeJS")
    root = tk.Tk()
    app = UltimateMCScanner(root)
    root.mainloop()
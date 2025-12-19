"""
Zewail Bank - Minimal Edition
Screens: Home, Deposit, Withdraw, Transfer, Card, Transactions
"""

import customtkinter as ctk
import json, os, random, time, csv
from tkinter import messagebox, Canvas, filedialog
import hashlib

# ========= Config =========
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

DB = "bank_db.json"
ACTIVITY_LOG = "activity_log.txt"
NEON = "#00F5A8"
BG = "#071014"
APP_TITLE = "Zewail Bank — Advanced (Lite)"
VERSION = "2.0"
SESSION_TIMEOUT = 300
MAX_LOGIN_ATTEMPTS = 3

EXCHANGE_RATES = {"EGP": 1.0, "USD": 0.032, "EUR": 0.030, "QAR": 0.117, "SAR": 0.121}
CURRENCY_SYMBOLS = {"EGP": "E£", "USD": "$", "EUR": "€", "QAR": "QR", "SAR": "SR"}

try:
    import pyperclip
except:
    pyperclip = None

# ========= Helpers =========

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def gen_iban() -> str:
    return "EG" + "".join(str(random.randint(0, 9)) for _ in range(18))

def gen_card() -> dict:
    num = " ".join("".join(str(random.randint(0, 9)) for _ in range(4)) for _ in range(4))
    return {
        "number": num,
        "cvv": f"{random.randint(0, 999):03d}",
        "exp": f"{random.randint(1, 12):02d}/{random.randint(25, 30)}",
    }

def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log_activity(username: str, action: str) -> None:
    try:
        with open(ACTIVITY_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{now()}] {username}: {action}\n")
    except:
        pass

def convert_currency(amount: float, from_curr: str, to_curr: str) -> float:
    egp = amount / EXCHANGE_RATES[from_curr]
    return egp * EXCHANGE_RATES[to_curr]

def load_db() -> dict:
    if not os.path.exists(DB):
        with open(DB, "w", encoding="utf-8") as f:
            json.dump({"users": {}, "settings": {}}, f)
    with open(DB, "r", encoding="utf-8") as f:
        try:
            d = json.load(f)
        except:
            d = {"users": {}, "settings": {}}
    d.setdefault("users", {})
    d.setdefault("settings", {})
    return d

def save_db(d: dict) -> None:
    with open(DB, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

db = load_db()

# ========= UI Widgets =========

class MastercardLogo(Canvas):
    def __init__(self, parent, size: int = 40):
        super().__init__(parent, width=size * 1.8, height=size, bg="#121826", highlightthickness=0)
        s = size
        self.create_oval(0, 0, s, s, fill="#EB001B", outline="")
        self.create_oval(s * 0.8, 0, s * 1.8, s, fill="#FF5F00", outline="")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        try:
            self.attributes("-fullscreen", True)
        except:
            self.state("zoomed")
        self.bind("<Escape>", lambda e: self.attributes("-fullscreen", False))
        self.configure(fg_color=BG)

        self.user = None
        self.last_activity = time.time()
        self.login_attempts = {}

        self.setup_sidebar()
        self.setup_main()
        self.setup_sections()
        self.check_session()

    # ----- layout -----
    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=260, fg_color="#071822")
        self.sidebar.pack(side="left", fill="y", padx=12, pady=12)

        ctk.CTkLabel(self.sidebar, text="Zewail Bank", font=("Inter", 20, "bold"),
                     text_color=NEON).pack(pady=(6, 2))
        ctk.CTkLabel(self.sidebar, text=f"v{VERSION}", font=("Inter", 9),
                     text_color="#666").pack(pady=(0, 12))

        nav = [
            ("🏠 Home", "home"),
            ("💰 Deposit", "deposit"),
            ("💸 Withdraw", "withdraw"),
            ("🔄 Transfer", "transfer"),
            ("💳 Card", "card"),
            ("📊 Transactions", "txs"),
        ]

        for text, key in nav:
            ctk.CTkButton(
                self.sidebar, text=text, width=220,
                fg_color="#0b2a2a", hover_color="#0e3535", anchor="w",
                command=lambda k=key: self.show_section(k)
            ).pack(pady=4)

        self.user_label = ctk.CTkLabel(self.sidebar, text="Not logged in", font=("Inter", 11))
        self.user_label.pack(side="bottom", pady=8)

        self.logout_btn = ctk.CTkButton(
            self.sidebar, text="🚪 Logout", width=220,
            fg_color="#8B0000", command=self.logout
        )
        self.logout_btn.pack(side="bottom", pady=6)
        self.logout_btn.pack_forget()

    def setup_main(self):
        self.main = ctk.CTkFrame(self, fg_color="#06121a")
        self.main.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=12)
        self.sections = {}
        self.auth_frame = AuthFrame(self.main, self)
        self.auth_frame.place(relx=0.5, rely=0.5, anchor="center")

    def setup_sections(self):
        for cls, key in [
            (HomeSection, "home"),
            (DepositSection, "deposit"),
            (WithdrawSection, "withdraw"),
            (TransferSection, "transfer"),
            (CardSection, "card"),
            (TransactionsSection, "txs"),
        ]:
            f = cls(self.main, self)
            f.place(relwidth=1, relheight=1, x=0, y=0)
            self.sections[key] = f
        self.show_section("home")

    # ----- session -----
    def show_section(self, key: str):
        protected = {"home", "deposit", "withdraw", "transfer", "card", "txs"}
        if key in protected and not self.user:
            self.auth_frame.lift()
            return
        self.last_activity = time.time()
        self.auth_frame.lower()
        for k, frame in self.sections.items():
            if k == key:
                frame.lift()
            else:
                frame.lower()
        for s in self.sections.values():
            if hasattr(s, "on_show"):
                s.on_show()

    def check_session(self):
        if self.user and (time.time() - self.last_activity) > SESSION_TIMEOUT:
            self.logout(timeout=True)
        self.after(10000, self.check_session)

    # ----- auth / db ops -----
    def login(self, username: str, password: str) -> bool:
        if username in self.login_attempts:
            attempts, last_time = self.login_attempts[username]
            if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_time) < 300:
                messagebox.showerror("Locked", "Too many attempts. Wait 5 minutes.")
                return False
            elif (time.time() - last_time) >= 300:
                self.login_attempts[username] = [0, time.time()]

        hashed = hash_password(password)
        if username in db["users"] and db["users"][username]["password"] == hashed:
            self.user = username
            self.last_activity = time.time()
            self.user_label.configure(text=f"👤 @{username}")
            self.logout_btn.pack(side="bottom", pady=6)

            udata = db["users"][username]
            for key, default in [("transactions", []), ("card", gen_card()), ("currency", "EGP")]:
                udata.setdefault(key, default)
            save_db(db)

            log_activity(username, "Logged in")
            messagebox.showinfo("Welcome", f"Welcome {username}!")
            self.show_section("home")
            if username in self.login_attempts:
                del self.login_attempts[username]
            return True

        if username not in self.login_attempts:
            self.login_attempts[username] = [0, time.time()]
        attempts, _ = self.login_attempts[username]
        self.login_attempts[username] = [attempts + 1, time.time()]
        remaining = MAX_LOGIN_ATTEMPTS - (attempts + 1)
        if remaining > 0:
            messagebox.showerror("Failed", f"Invalid credentials. {remaining} attempts left.")
        log_activity(username, "Failed login")
        return False

    def logout(self, timeout: bool = False):
        if self.user:
            log_activity(self.user, "Logged out" if not timeout else "Timeout")
        self.user = None
        self.user_label.configure(text="Not logged in")
        self.logout_btn.pack_forget()
        self.show_section("home")
        msg = "Session expired due to inactivity." if timeout else "Logged out successfully."
        messagebox.showinfo("Logout", msg)

    def create_account(self, username: str, password: str, email: str = ""):
        if username in db["users"]:
            return False, "Username exists"
        if len(password) < 6:
            return False, "Password must be 6+ characters"
        db["users"][username] = {
            "password": hash_password(password),
            "balance": 0.0,
            "iban": gen_iban(),
            "card": gen_card(),
            "email": email,
            "transactions": [],
            "created_at": now(),
            "currency": "EGP",
        }
        save_db(db)
        log_activity(username, "Account created")
        return True, None

    def deposit(self, amt: str):
        if not self.user:
            return False, "Not logged in"
        try:
            v = float(amt)
            if v <= 0:
                return False, "Must be positive"
        except:
            return False, "Invalid amount"
        u = self.user
        db["users"][u]["balance"] += v
        db["users"][u]["transactions"].append({
            "time": now(), "type": "Deposit", "amount": v,
            "currency": db["users"][u]["currency"],
        })
        save_db(db)
        log_activity(u, f"Deposited {v}")
        return True, None

    def withdraw(self, amt: str):
        if not self.user:
            return False, "Not logged in"
        try:
            v = float(amt)
            if v <= 0:
                return False, "Must be positive"
        except:
            return False, "Invalid amount"
        u = self.user
        if v > db["users"][u]["balance"]:
            return False, "Insufficient funds"
        db["users"][u]["balance"] -= v
        db["users"][u]["transactions"].append({
            "time": now(), "type": "Withdraw", "amount": v,
            "currency": db["users"][u]["currency"],
        })
        save_db(db)
        log_activity(u, f"Withdrew {v}")
        return True, None

    def transfer(self, target: str, amt: str):
        if not self.user:
            return False, "Not logged in"
        try:
            v = float(amt)
            if v <= 0:
                return False, "Must be positive"
        except:
            return False, "Invalid amount"

        u = self.user
        if target == u:
            return False, "Cannot transfer to self"

        tgt = None
        if target in db["users"]:
            tgt = target
        else:
            for name, info in db["users"].items():
                if info.get("iban") == target:
                    tgt = name
                    break
        if not tgt:
            return False, "Recipient not found"
        if v > db["users"][u]["balance"]:
            return False, "Insufficient funds"

        db["users"][u]["balance"] -= v
        db["users"][tgt]["balance"] += v
        curr = db["users"][u]["currency"]
        db["users"][u]["transactions"].append({
            "time": now(), "type": "Transfer Out", "amount": v, "to": tgt, "currency": curr,
        })
        db["users"][tgt]["transactions"].append({
            "time": now(), "type": "Transfer In", "amount": v, "from": u, "currency": curr,
        })
        save_db(db)
        log_activity(u, f"Transferred {v} to {tgt}")
        return True, None

# ========= Frames =========

class AuthFrame(ctk.CTkFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, width=700, height=520, corner_radius=12, fg_color="#071320")
        self.app = app

        ctk.CTkLabel(self, text="🏦 Zewail Bank", font=("Inter", 24, "bold"),
                     text_color=NEON).pack(pady=(18, 4))
        ctk.CTkLabel(self, text="Secure Digital Banking",
                     font=("Inter", 12), text_color="#888").pack(pady=(0, 12))

        self.form = ctk.CTkFrame(self, fg_color="transparent")
        self.form.pack(pady=6)

        for i, (lbl, ph) in enumerate([
            ("Username", "Enter username"),
            ("Password", "Enter password (6+ chars)"),
            ("Email", "email@example.com (optional)"),
        ]):
            ctk.CTkLabel(self.form, text=lbl).grid(row=i, column=0, sticky="w", padx=6, pady=6)
            entry = ctk.CTkEntry(self.form, width=360, placeholder_text=ph)
            if i == 1:
                entry.configure(show="*")
                self.p = entry
            elif i == 0:
                self.u = entry
            else:
                self.email = entry
            entry.grid(row=i, column=1, padx=6, pady=6)

        btnf = ctk.CTkFrame(self.form, fg_color="transparent")
        btnf.grid(row=4, column=0, columnspan=2, pady=12)

        ctk.CTkButton(
            btnf, text="🔐 Login", fg_color=NEON, text_color="black",
            width=170, height=40, command=self.try_login
        ).grid(row=0, column=0, padx=6)

        ctk.CTkButton(
            btnf, text="📝 Sign Up", fg_color="#2b2b2b",
            width=170, height=40, command=self.try_create
        ).grid(row=0, column=1, padx=6)

    def try_login(self):
        u, p = self.u.get().strip(), self.p.get().strip()
        if not (u and p):
            messagebox.showerror("Error", "Enter credentials")
            return
        self.app.login(u, p)

    def try_create(self):
        u, p = self.u.get().strip(), self.p.get().strip()
        e = self.email.get().strip()
        if not (u and p):
            messagebox.showerror("Error", "Enter username & password")
            return
        ok, msg = self.app.create_account(u, p, e)
        if not ok:
            messagebox.showerror("Failed", msg)
            return
        messagebox.showinfo("Success", "Account created! Please login.")
        for entry in [self.u, self.p, self.email]:
            entry.delete(0, "end")

class HomeSection(ctk.CTkScrollableFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, fg_color="#061a20")
        self.app = app

        ctk.CTkLabel(self, text="📊 Dashboard", font=("Inter", 28, "bold"),
                     text_color=NEON).pack(pady=12)

        bf = ctk.CTkFrame(self, fg_color="#0a1f2e", corner_radius=12)
        bf.pack(pady=12, padx=20, fill="x")
        ctk.CTkLabel(bf, text="💰 Balance", font=("Inter", 14)).pack(pady=(12, 4))
        self.balance = ctk.CTkLabel(bf, text="0.00 EGP",
                                    font=("Inter", 36, "bold"), text_color=NEON)
        self.balance.pack(pady=8)
        self.balance_usd = ctk.CTkLabel(
            bf, text="≈ $0.00", font=("Inter", 12), text_color="#888"
        )
        self.balance_usd.pack(pady=(0, 12))

        inf = ctk.CTkFrame(self, fg_color="#0a1f2e", corner_radius=12)
        inf.pack(pady=12, padx=20, fill="x")
        self.iban_label = ctk.CTkLabel(inf, text="IBAN: -", font=("Inter", 12))
        self.iban_label.pack(pady=8)
        self.created_label = ctk.CTkLabel(
            inf, text="Member since: -", font=("Inter", 10), text_color="#888"
        )
        self.created_label.pack(pady=(0, 8))

        qf = ctk.CTkFrame(self, fg_color="transparent")
        qf.pack(pady=12)
        for i, (txt, sec) in enumerate([
            ("Deposit", "deposit"),
            ("Withdraw", "withdraw"),
            ("Transfer", "transfer"),
            ("Card", "card"),
        ]):
            ctk.CTkButton(
                qf, text=txt, width=140,
                command=lambda s=sec: self.app.show_section(s)
            ).grid(row=0, column=i, padx=8)

        ctk.CTkLabel(
            self, text="📝 Recent Transactions",
            font=("Inter", 16, "bold"), text_color=NEON
        ).pack(pady=(20, 8))
        self.recent = ctk.CTkTextbox(self, width=820, height=250)
        self.recent.pack(pady=12)

    def on_show(self):
        u = self.app.user
        if not u:
            return
        ud = db["users"][u]
        bal = ud["balance"]
        curr = ud["currency"]
        sym = CURRENCY_SYMBOLS[curr]
        self.balance.configure(text=f"{sym}{bal:.2f}")
        usd = convert_currency(bal, curr, "USD")
        self.balance_usd.configure(text=f"≈ ${usd:.2f}")
        self.iban_label.configure(text=f"IBAN: {ud['iban']}")
        self.created_label.configure(text=f"Member since: {ud.get('created_at', 'N/A')}")
        txs = ud.get("transactions", [])[-10:]
        lines = [f"{t['time']} | {t['type']} | {t['amount']:.2f}" for t in reversed(txs)]
        self.recent.delete("0.0", "end")
        self.recent.insert("0.0", "\n".join(lines) if lines else "No transactions")

class DepositSection(ctk.CTkFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, fg_color="#061a20")
        self.app = app
        ctk.CTkLabel(self, text="💰 Deposit", font=("Inter", 20, "bold"),
                     text_color=NEON).pack(pady=12)
        self.amount = ctk.CTkEntry(self, placeholder_text="Amount", width=300)
        self.amount.pack(pady=8)
        ctk.CTkButton(
            self, text="Deposit", fg_color=NEON, text_color="black",
            command=self.do
        ).pack(pady=8)

    def do(self):
        amt = self.amount.get().strip()
        ok, msg = self.app.deposit(amt)
        if not ok:
            messagebox.showerror("Error", msg)
            return
        messagebox.showinfo("Done", f"Deposited {amt}")
        self.amount.delete(0, "end")
        self.app.show_section("home")

class WithdrawSection(ctk.CTkFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, fg_color="#061a20")
        self.app = app
        ctk.CTkLabel(self, text="💸 Withdraw", font=("Inter", 20, "bold"),
                     text_color=NEON).pack(pady=12)
        self.amount = ctk.CTkEntry(self, placeholder_text="Amount", width=300)
        self.amount.pack(pady=8)
        ctk.CTkButton(
            self, text="Withdraw", fg_color=NEON, text_color="black",
            command=self.do
        ).pack(pady=8)

    def do(self):
        amt = self.amount.get().strip()
        ok, msg = self.app.withdraw(amt)
        if not ok:
            messagebox.showerror("Error", msg)
            return
        messagebox.showinfo("Done", f"Withdrew {amt}")
        self.amount.delete(0, "end")
        self.app.show_section("home")

class TransferSection(ctk.CTkFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, fg_color="#061a20")
        self.app = app
        ctk.CTkLabel(self, text="🔄 Transfer", font=("Inter", 20, "bold"),
                     text_color=NEON).pack(pady=12)
        self.target = ctk.CTkEntry(self, placeholder_text="Username or IBAN", width=420)
        self.target.pack(pady=8)
        self.amount = ctk.CTkEntry(self, placeholder_text="Amount", width=220)
        self.amount.pack(pady=8)
        ctk.CTkButton(
            self, text="Send", fg_color=NEON, text_color="black",
            command=self.do
        ).pack(pady=8)

    def do(self):
        t = self.target.get().strip()
        a = self.amount.get().strip()
        ok, msg = self.app.transfer(t, a)
        if not ok:
            messagebox.showerror("Error", msg)
            return
        messagebox.showinfo("Done", f"Sent {a} to {t}")
        self.target.delete(0, "end")
        self.amount.delete(0, "end")
        self.app.show_section("home")

class CardSection(ctk.CTkFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, fg_color="#061a20")
        self.app = app

        ctk.CTkLabel(self, text="💳 Virtual Mastercard", font=("Inter", 20, "bold"),
                     text_color=NEON).pack(pady=12)

        self.card_frame = ctk.CTkFrame(self, width=500, height=280,
                                       fg_color="#121826", corner_radius=16)
        self.card_frame.place(relx=0.5, rely=0.38, anchor="center")

        ctk.CTkLabel(self.card_frame, text="Zewail Bank",
                     font=("Inter", 18, "bold"), text_color=NEON).place(x=20, y=15)
        self.logo = MastercardLogo(self.card_frame, size=35)
        self.logo.place(x=420, y=15)

        self.num = ctk.CTkLabel(
            self.card_frame, text="---- ---- ---- ----",
            font=("Consolas", 22, "bold"), text_color="white"
        )
        self.num.place(x=20, y=110)

        ctk.CTkLabel(self.card_frame, text="EXP",
                     font=("Inter", 10), text_color="#aaa").place(x=20, y=170)
        self.exp_label = ctk.CTkLabel(
            self.card_frame, text="--/--",
            font=("Inter", 14, "bold"), text_color="white"
        )
        self.exp_label.place(x=60, y=168)

        ctk.CTkLabel(self.card_frame, text="CVV",
                     font=("Inter", 10), text_color="#aaa").place(x=160, y=170)
        self.cvv_label = ctk.CTkLabel(
            self.card_frame, text="---",
            font=("Inter", 14, "bold"), text_color="white"
        )
        self.cvv_label.place(x=190, y=168)

        ctk.CTkLabel(self.card_frame, text="CARDHOLDER",
                     font=("Inter", 10), text_color="#aaa").place(x=20, y=210)
        self.cardholder_name = ctk.CTkLabel(
            self.card_frame, text="NAME",
            font=("Inter", 14, "bold"), text_color="white"
        )
        self.cardholder_name.place(x=20, y=230)

        btnf = ctk.CTkFrame(self, fg_color="transparent")
        btnf.pack(pady=20, side="bottom")
        ctk.CTkButton(
            btnf, text="🔄 Regenerate", fg_color=NEON, text_color="black",
            command=self.regen, width=150
        ).grid(row=0, column=0, padx=8)
        ctk.CTkButton(
            btnf, text="📋 Copy Number", fg_color="#2b2b2b",
            command=self.copy_num, width=140
        ).grid(row=0, column=1, padx=8)
        ctk.CTkButton(
            btnf, text="📋 Copy CVV", fg_color="#2b2b2b",
            command=self.copy_cvv, width=140
        ).grid(row=0, column=2, padx=8)

    def on_show(self):
        u = self.app.user
        if not u:
            return
        c = db["users"][u]["card"]
        self.num.configure(text=c["number"])
        self.exp_label.configure(text=c["exp"])
        self.cvv_label.configure(text=c["cvv"])
        self.cardholder_name.configure(text=u.upper())

    def regen(self):
        u = self.app.user
        if not u:
            return
        if not messagebox.askyesno("Confirm", "Generate new card? Old card will be invalid."):
            return
        db["users"][u]["card"] = gen_card()
        save_db(db)
        self.on_show()
        messagebox.showinfo("Done", "New card generated")

    def copy_num(self):
        if pyperclip and self.app.user:
            pyperclip.copy(db["users"][self.app.user]["card"]["number"])
            messagebox.showinfo("Copied", "Card number copied")

    def copy_cvv(self):
        if pyperclip and self.app.user:
            pyperclip.copy(db["users"][self.app.user]["card"]["cvv"])
            messagebox.showinfo("Copied", "CVV copied")

class TransactionsSection(ctk.CTkScrollableFrame):
    def __init__(self, parent, app: App):
        super().__init__(parent, fg_color="#061a20")
        self.app = app

        ctk.CTkLabel(self, text="📊 Transactions", font=("Inter", 20, "bold"),
                     text_color=NEON).pack(pady=12)

        ff = ctk.CTkFrame(self, fg_color="#0a1f2e")
        ff.pack(pady=8, padx=20, fill="x")
        ctk.CTkLabel(ff, text="Filter:", font=("Inter", 12, "bold")).pack(side="left", padx=10)

        self.filter_type = ctk.CTkComboBox(
            ff, values=["All", "Deposit", "Withdraw", "Transfer In", "Transfer Out"],
            width=150
        )
        self.filter_type.set("All")
        self.filter_type.pack(side="left", padx=5)

        ctk.CTkButton(ff, text="🔍 Apply", width=100,
                      command=self.apply_filter).pack(side="left", padx=5)
        ctk.CTkButton(
            ff, text="📥 Export CSV", width=120, fg_color=NEON, text_color="black",
            command=self.export_csv
        ).pack(side="left", padx=5)

        self.box = ctk.CTkTextbox(self, width=900, height=450, font=("Consolas", 10))
        self.box.pack(pady=12, padx=20, fill="both", expand=True)

    def on_show(self):
        self.apply_filter()

    def apply_filter(self):
        self.box.delete("0.0", "end")
        u = self.app.user
        if not u:
            self.box.insert("0.0", "Not logged in")
            return

        txs = db["users"][u].get("transactions", [])
        filter_val = self.filter_type.get()
        if filter_val != "All":
            txs = [t for t in txs if t["type"] == filter_val]

        if not txs:
            self.box.insert("0.0", "No transactions")
            return

        for t in reversed(txs):
            line = f"{t['time']:20s} | {t['type']:15s} | {t['amount']:10.2f}"
            if t.get("to"):
                line += f" -> {t['to']}"
            if t.get("from"):
                line += f" <- {t['from']}"
            self.box.insert("end", line + "\n")

    def export_csv(self):
        u = self.app.user
        if not u:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")]
        )
        if not path:
            return
        txs = db["users"][u].get("transactions", [])
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Type", "Amount", "Currency", "To/From"])
            for t in txs:
                extra = t.get("to", t.get("from", ""))
                writer.writerow([t["time"], t["type"], t["amount"],
                                 t.get("currency", "EGP"), extra])
        messagebox.showinfo("Success", f"Exported to {path}")

# ========= Main =========

if __name__ == "__main__":
    app = App()
    app.mainloop()

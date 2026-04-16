import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import urllib.parse
from datetime import datetime
from http import cookies
from http.server import HTTPServer, BaseHTTPRequestHandler

APP_NAME = "RiskAuth 2FA"
DB_PATH = "risk_auth.db"
HOST = "127.0.0.1"
PORT = 5000
SESSION_COOKIE = "riskauth_session"
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")
SESSIONS = {}


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def check_password(password, stored):
    try:
        alg, salt, digest = stored.split("$", 2)
        if alg != "pbkdf2_sha256":
            return False
        new_digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000).hex()
        return hmac.compare_digest(new_digest, digest)
    except Exception:
        return False


def sign(value):
    sig = hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def unsign(value):
    try:
        raw, sig = value.rsplit(".", 1)
        good = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, good):
            return raw
    except Exception:
        pass
    return None


def get_user(username):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def page(title, body, user=None):
    username = html.escape(user["username"]) if user else ""
    links = "<a href='/dashboard'>Кабинет</a><a href='/logout'>Выйти (" + username + ")</a>" if user else "<a href='/register'>Регистрация</a><a href='/login'>Вход</a>"
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:Arial,sans-serif;background:#f4f6f8;margin:0;color:#1f2937}}header{{background:#111827;color:white;padding:22px 32px}}nav{{background:white;padding:12px 32px;border-bottom:1px solid #ddd}}nav a{{margin-right:18px;color:#2563eb;text-decoration:none;font-weight:bold}}main{{max-width:900px;margin:30px auto;background:white;padding:28px;border-radius:14px}}input,button{{padding:10px;margin:6px 0;border-radius:8px;border:1px solid #cbd5e1}}input{{width:100%;box-sizing:border-box}}button{{background:#2563eb;color:white;border:0;font-weight:bold}}.bad{{color:#b91c1c;font-weight:bold}}.ok{{color:#15803d;font-weight:bold}}</style>
</head><body><header><h1>{APP_NAME}</h1></header><nav><a href='/'>Главная</a>{links}</nav><main>{body}</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def parse_cookies(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie"))
        return {k: v.value for k, v in c.items()}

    def current_user(self):
        sid_signed = self.parse_cookies().get(SESSION_COOKIE)
        sid = unsign(sid_signed) if sid_signed else None
        if not sid or sid not in SESSIONS:
            return None
        uid = SESSIONS[sid]["user_id"]
        with db() as conn:
            return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    def send_html(self, text, status=200, extra_headers=None):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def redirect(self, path, set_cookie=None):
        self.send_response(302); self.send_header("Location", path)
        if set_cookie: self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def form_data(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8")
        return {k: v[0] if v else "" for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self):
        user = self.current_user()
        if self.path == "/": self.send_html(page("Главная", "<h2>Главная</h2><p>Регистрация, вход и кабинет пользователя.</p>", user))
        elif self.path == "/register": self.send_html(page("Регистрация", "<h2>Регистрация</h2><form method='post'><label>Логин</label><input name='username' required><label>Email</label><input name='email' type='email' required><label>Пароль</label><input name='password' type='password' required><button>Создать аккаунт</button></form>", user))
        elif self.path == "/login": self.send_html(page("Вход", "<h2>Вход</h2><form method='post'><label>Логин</label><input name='username' required><label>Пароль</label><input name='password' type='password' required><button>Войти</button></form>", user))
        elif self.path == "/dashboard":
            if not user: self.redirect("/login"); return
            self.send_html(page("Кабинет", f"<h2>Кабинет</h2><p class='ok'>Вы вошли в систему.</p><p>Пользователь: <b>{html.escape(user['username'])}</b></p><p>Email: {html.escape(user['email'])}</p>", user))
        elif self.path == "/logout":
            sid = unsign(self.parse_cookies().get(SESSION_COOKIE, "") or "")
            if sid: SESSIONS.pop(sid, None)
            self.redirect("/", f"{SESSION_COOKIE}=; Max-Age=0; Path=/")
        else: self.send_html(page("404", "<h2>Страница не найдена</h2>", user), 404)

    def do_POST(self):
        data = self.form_data(); user = self.current_user()
        if self.path == "/register":
            try:
                with db() as conn:
                    conn.execute("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)", (data.get('username','').strip(), data.get('email','').strip(), password_hash(data.get('password','')), now_str()))
                self.send_html(page("Регистрация", "<p class='ok'>Пользователь создан.</p><p><a href='/login'>Перейти ко входу</a></p>", user))
            except sqlite3.IntegrityError:
                self.send_html(page("Ошибка", "<p class='bad'>Такой логин уже существует.</p>", user), 400)
        elif self.path == "/login":
            u = get_user(data.get("username", "").strip())
            if not u or not check_password(data.get("password", ""), u["password_hash"]):
                self.send_html(page("Ошибка", "<p class='bad'>Неверный логин или пароль.</p>", None), 401); return
            sid = secrets.token_urlsafe(24); SESSIONS[sid] = {"user_id": u["id"]}
            self.redirect("/dashboard", f"{SESSION_COOKIE}={sign(sid)}; HttpOnly; Path=/; SameSite=Lax")
        else: self.send_html(page("404", "<h2>Страница не найдена</h2>", user), 404)


if __name__ == "__main__":
    init_db(); print(f"Сервер запущен: http://{HOST}:{PORT}"); HTTPServer((HOST, PORT), Handler).serve_forever()

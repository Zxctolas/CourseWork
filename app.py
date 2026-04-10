import html
import sqlite3
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

APP_NAME = "RiskAuth 2FA"
DB_PATH = "risk_auth.db"
HOST = "127.0.0.1"
PORT = 5000


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
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_user(username):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def page(title, body):
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body{{font-family:Arial,sans-serif;background:#f4f6f8;margin:0;color:#1f2937}}header{{background:#111827;color:white;padding:22px 32px}}nav{{background:white;padding:12px 32px;border-bottom:1px solid #ddd}}nav a{{margin-right:18px;color:#2563eb;text-decoration:none;font-weight:bold}}main{{max-width:900px;margin:30px auto;background:white;padding:28px;border-radius:14px}}input,button{{padding:10px;margin:6px 0;border-radius:8px;border:1px solid #cbd5e1}}input{{width:100%;box-sizing:border-box}}button{{background:#2563eb;color:white;border:0;font-weight:bold}}.bad{{color:#b91c1c;font-weight:bold}}.ok{{color:#15803d;font-weight:bold}}
</style></head><body><header><h1>{APP_NAME}</h1></header><nav><a href='/'>Главная</a><a href='/register'>Регистрация</a><a href='/login'>Вход</a></nav><main>{body}</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def send_html(self, text, status=200):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path):
        self.send_response(302)
        self.send_header("Location", path)
        self.end_headers()

    def form_data(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        return {k: v[0] if v else "" for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self):
        if self.path == "/":
            body = "<h2>Главная</h2><p>Приложение для регистрации и входа пользователя.</p>"
            self.send_html(page("Главная", body))
        elif self.path == "/register":
            body = """
            <h2>Регистрация</h2>
            <form method="post">
                <label>Логин</label><input name="username" required>
                <label>Email</label><input name="email" type="email" required>
                <label>Пароль</label><input name="password" type="password" required>
                <button>Создать аккаунт</button>
            </form>
            """
            self.send_html(page("Регистрация", body))
        elif self.path == "/login":
            body = """
            <h2>Вход</h2>
            <form method="post">
                <label>Логин</label><input name="username" required>
                <label>Пароль</label><input name="password" type="password" required>
                <button>Войти</button>
            </form>
            """
            self.send_html(page("Вход", body))
        else:
            self.send_html(page("404", "<h2>Страница не найдена</h2>"), 404)

    def do_POST(self):
        data = self.form_data()
        if self.path == "/register":
            username = data.get("username", "").strip()
            email = data.get("email", "").strip()
            password = data.get("password", "")
            try:
                with db() as conn:
                    conn.execute("INSERT INTO users(username,email,password,created_at) VALUES(?,?,?,?)", (username, email, password, now_str()))
                self.send_html(page("Регистрация", "<p class='ok'>Пользователь создан.</p><p><a href='/login'>Перейти ко входу</a></p>"))
            except sqlite3.IntegrityError:
                self.send_html(page("Ошибка", "<p class='bad'>Такой логин уже существует.</p>"), 400)
        elif self.path == "/login":
            username = data.get("username", "").strip()
            password = data.get("password", "")
            user = get_user(username)
            if user and user["password"] == password:
                self.send_html(page("Вход", f"<p class='ok'>Вход выполнен.</p><p>Пользователь: <b>{html.escape(username)}</b></p>"))
            else:
                self.send_html(page("Ошибка входа", "<p class='bad'>Неверный логин или пароль.</p>"), 401)
        else:
            self.send_html(page("404", "<h2>Страница не найдена</h2>"), 404)


if __name__ == "__main__":
    init_db()
    print(f"Сервер запущен: http://{HOST}:{PORT}")
    HTTPServer((HOST, PORT), Handler).serve_forever()

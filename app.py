# Этап 5: добавлена балльная оценка риска
import base64
import csv
import hashlib
import hmac
import html
import io
import os
import secrets
import sqlite3
import struct
import time
import urllib.parse
from datetime import datetime
from http import cookies
from http.server import HTTPServer, BaseHTTPRequestHandler

APP_NAME = "RiskAuth 2FA"
APP_SUBTITLE = "Система двухфакторной аутентификации с интеллектуальным анализом подозрительных входов"
DB_PATH = "risk_auth.db"
HOST = "127.0.0.1"
PORT = 5000
SESSION_COOKIE = "riskauth_session"
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-for-coursework-demo")
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
            totp_secret TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            login_time TEXT,
            success INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            decision TEXT,
            reason TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_fingerprint TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, device_fingerprint),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
        # Совместимость со старой версией БД, где колонки decision могло не быть.
        columns = [row[1] for row in conn.execute("PRAGMA table_info(login_attempts)").fetchall()]
        if "decision" not in columns:
            conn.execute("ALTER TABLE login_attempts ADD COLUMN decision TEXT")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        alg, salt, digest = stored.split("$", 2)
        if alg != "pbkdf2_sha256":
            return False
        new_digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000).hex()
        return hmac.compare_digest(new_digest, digest)
    except Exception:
        return False


def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode().replace("=", "")


def hotp(secret: str, counter: int, digits: int = 6) -> str:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode((secret + padding).upper())
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7fffffff
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: str, for_time=None, step: int = 30) -> str:
    if for_time is None:
        for_time = int(time.time())
    return hotp(secret, int(for_time // step))


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    t = int(time.time())
    for offset in range(-window, window + 1):
        if hmac.compare_digest(totp(secret, t + offset * 30), code):
            return True
    return False


def fingerprint(user_agent: str) -> str:
    return hashlib.sha256((user_agent or "unknown").encode()).hexdigest()


def get_user(username: str):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def count_recent_failed(username: str):
    with db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS c FROM login_attempts
            WHERE username = ? AND success = 0
              AND login_time >= datetime('now', '-15 minutes')
            """,
            (username,),
        ).fetchone()
        return int(row["c"] or 0)


def is_known_device(user_id: int, fp: str):
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM trusted_devices WHERE user_id = ? AND device_fingerprint = ?",
            (user_id, fp),
        ).fetchone()
        return row is not None


def last_success_ip(user_id: int):
    with db() as conn:
        row = conn.execute(
            """
            SELECT ip_address FROM login_attempts
            WHERE user_id = ? AND success = 1
            ORDER BY id DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        return row["ip_address"] if row else None


def risk_level_by_score(score: int):
    if score < 30:
        return "низкий"
    if score < 60:
        return "средний"
    return "высокий"


def decision_by_level(level: str):
    if level == "низкий":
        return "допуск к 2FA"
    if level == "средний":
        return "допуск к 2FA, запись как подозрительная попытка"
    return "блокировка входа до этапа 2FA"


def calculate_risk(user, username: str, ip: str, ua: str):
    score = 0
    factors = []

    failed = count_recent_failed(username)
    if failed >= 3:
        score += 25
        factors.append(("3+ неудачных попытки за последние 15 минут", 25))
    elif failed > 0:
        add = failed * 5
        score += add
        factors.append((f"неудачные попытки входа за последние 15 минут: {failed}", add))

    hour = datetime.now().hour
    if hour < 6 or hour >= 23:
        score += 10
        factors.append(("нетипичное ночное время входа", 10))

    if user:
        fp = fingerprint(ua)
        if not is_known_device(user["id"], fp):
            score += 15
            factors.append(("новый браузер или устройство", 15))

        prev_ip = last_success_ip(user["id"])
        if prev_ip and prev_ip != ip:
            score += 20
            factors.append(("новый IP-адрес по сравнению с прошлым успешным входом", 20))

    # Демонстрационные IP: позволяют проверить высокий риск без VPN.
    if ip.startswith("8.8.8.") or ip.startswith("185.") or ip.startswith("45."):
        score += 30
        factors.append(("демо-признак: подозрительная внешняя сеть", 30))

    level = risk_level_by_score(score)
    decision = decision_by_level(level)

    if not factors:
        reason = "подозрительных признаков не обнаружено"
    else:
        reason = "; ".join([f"{name} (+{points})" for name, points in factors])

    return score, level, decision, reason, factors


def log_attempt(user_id, username, ip, ua, success, score, level, decision, reason):
    with db() as conn:
        conn.execute(
            """
            INSERT INTO login_attempts
            (user_id, username, ip_address, user_agent, login_time, success, risk_score, risk_level, decision, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, ip, ua, now_str(), int(success), score, level, decision, reason),
        )


def remember_device(user_id: int, ip: str, ua: str):
    with db() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO trusted_devices(user_id, device_fingerprint, ip_address, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, fingerprint(ua), ip, now_str()),
        )


def user_stats(username: str):
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username = ?", (username,)).fetchone()["c"]
        success = conn.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username = ? AND success = 1", (username,)).fetchone()["c"]
        blocked = conn.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username = ? AND risk_level = 'высокий'", (username,)).fetchone()["c"]
        suspicious = conn.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username = ? AND risk_level IN ('средний','высокий')", (username,)).fetchone()["c"]
        last = conn.execute("SELECT * FROM login_attempts WHERE username = ? ORDER BY id DESC LIMIT 1", (username,)).fetchone()
        return {
            "total": int(total or 0),
            "success": int(success or 0),
            "blocked": int(blocked or 0),
            "suspicious": int(suspicious or 0),
            "last": last,
        }


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


def e(value):
    return html.escape(str(value or ""))


def status_badge(level):
    cls = {"низкий": "low", "средний": "medium", "высокий": "high"}.get(level, "neutral")
    return f'<span class="badge {cls}">{e(level)}</span>'


def result_badge(row):
    if row["success"]:
        return '<span class="badge low">успех</span>'
    if row["risk_level"] == "высокий":
        return '<span class="badge high">заблокировано</span>'
    return '<span class="badge neutral">отказ</span>'


def render_page(title, body, user=None, flash=""):
    flash_html = f'<div class="flash">{e(flash)}</div>' if flash else ""
    username = e(user["username"]) if user else ""
    auth_links = (
        '<a href="/dashboard">Кабинет</a>'
        '<a href="/attempts">Журнал</a>'
        '<a href="/export">CSV-отчёт</a>'
        f'<a href="/logout">Выйти ({username})</a>'
    ) if user else '<a href="/register">Регистрация</a><a href="/login">Вход</a>'
    nav = f"""
    <nav>
      <a href="/">Главная</a>
      <a href="/about">Модель риска</a>
      <a href="/demo">Демо-сценарии</a>
      {auth_links}
    </nav>
    """
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} — {APP_NAME}</title>
<style>
:root{{--bg:#eef2f7;--text:#172033;--muted:#64748b;--card:#ffffff;--line:#e2e8f0;--blue:#2563eb;--green:#15803d;--yellow:#92400e;--red:#b91c1c}}
*{{box-sizing:border-box}}
body{{font-family:Arial, sans-serif;background:linear-gradient(135deg,#eef2f7,#f8fafc);margin:0;color:var(--text)}}
header{{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:white;padding:30px 34px}}
header h1{{margin:0 0 8px 0;font-size:30px}} header div{{opacity:.9;max-width:1000px}}
nav{{background:white;padding:13px 34px;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:2}}
nav a{{display:inline-block;margin:5px 18px 5px 0;color:var(--blue);text-decoration:none;font-weight:bold}}
main{{max-width:1100px;margin:28px auto;background:white;padding:28px;border-radius:18px;box-shadow:0 12px 40px #0f172a18}}
h2{{margin-top:0}} h3{{margin-top:26px}}
input,button{{padding:11px;margin:7px 0;border-radius:9px;border:1px solid #cbd5e1;font-size:15px}}
input{{width:100%;background:#fff}} button,.btn{{background:var(--blue);color:white;border:0;cursor:pointer;font-weight:bold;text-decoration:none;display:inline-block;padding:11px 16px;border-radius:9px;margin:5px 8px 5px 0}}
.btn.secondary{{background:#334155}} .btn.danger{{background:var(--red)}}
.flash{{background:#fef3c7;border:1px solid #f59e0b;padding:12px;border-radius:12px;margin-bottom:18px}}
.ok{{color:var(--green);font-weight:bold}} .bad{{color:var(--red);font-weight:bold}} .small{{color:var(--muted);font-size:14px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}} td,th{{border-bottom:1px solid var(--line);padding:10px;text-align:left;font-size:14px;vertical-align:top}} th{{background:#f8fafc}}
code{{background:#f1f5f9;padding:3px 6px;border-radius:6px;word-break:break-all}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:18px 0}}
.card{{background:#f8fafc;border:1px solid var(--line);padding:18px;border-radius:14px}}
.card b{{font-size:17px}} .card .num{{font-size:30px;font-weight:bold;margin:8px 0}}
.badge{{display:inline-block;border-radius:999px;padding:5px 10px;font-weight:bold;font-size:13px;white-space:nowrap}}
.badge.low{{background:#dcfce7;color:#166534}} .badge.medium{{background:#fef3c7;color:#92400e}} .badge.high{{background:#fee2e2;color:#991b1b}} .badge.neutral{{background:#e2e8f0;color:#334155}}
.hero{{display:grid;grid-template-columns:1.2fr .8fr;gap:20px;align-items:center}} .hero-panel{{background:#f8fafc;border:1px solid var(--line);padding:20px;border-radius:16px}}
.steps li{{margin:9px 0}} .riskbox{{border-left:5px solid var(--blue);background:#f8fafc;padding:14px;border-radius:12px;margin:12px 0}}
@media(max-width:760px){{.hero{{grid-template-columns:1fr}} main{{margin:14px;padding:18px}} header,nav{{padding-left:18px;padding-right:18px}}}}
</style>
</head>
<body>
<header><h1>{APP_NAME}</h1><div>{APP_SUBTITLE}</div></header>
{nav}
<main>{flash_html}{body}</main>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print("[%s] %s" % (self.log_date_time_string(), format % args))

    def parse_cookies(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie"))
        return {k: v.value for k, v in c.items()}

    def current_user(self):
        sid_signed = self.parse_cookies().get(SESSION_COOKIE)
        if not sid_signed:
            return None
        sid = unsign(sid_signed)
        if not sid or sid not in SESSIONS:
            return None
        uid = SESSIONS[sid].get("user_id")
        if not uid:
            return None
        with db() as conn:
            return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    def send_html(self, html_text, status=200, extra_headers=None):
        data = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, text, filename="report.csv"):
        data = text.encode("utf-8-sig")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path, set_cookie=None):
        self.send_response(302)
        self.send_header("Location", path)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def form_data(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        return {k: v[0] if v else "" for k, v in urllib.parse.parse_qs(raw).items()}

    def get_ip(self, query):
        params = urllib.parse.parse_qs(query)
        return params.get("demo_ip", [self.client_address[0]])[0]

    def render_home(self, user):
        body = """
<div class="hero">
  <section>
    <h2>RiskAuth 2FA</h2>
    <p>Небольшое веб-приложение для регистрации, входа по паролю, подтверждения через TOTP-код и проверки риска попытки входа.</p>
    <p>В приложении можно посмотреть обычный вход, вход с повышенным риском и журнал попыток.</p>
    <a class="btn" href="/register">Зарегистрировать пользователя</a>
    <a class="btn secondary" href="/demo">Демо-сценарии</a>
  </section>
  <aside class="hero-panel">
    <h3>Что анализируется</h3>
    <ul>
      <li>новый IP-адрес;</li>
      <li>новый браузер или устройство;</li>
      <li>ночное время входа;</li>
      <li>история неудачных попыток;</li>
      <li>демо-признак подозрительной сети.</li>
    </ul>
  </aside>
</div>
<div class="cards">
  <div class="card"><b>1. Пароль</b><p>Пароль хранится не открытым текстом, а в виде PBKDF2-хэша с солью.</p></div>
  <div class="card"><b>2. 2FA</b><p>Второй фактор реализован через TOTP-коды для приложений-аутентификаторов.</p></div>
  <div class="card"><b>3. Risk score</b><p>Каждому подозрительному признаку назначаются баллы риска.</p></div>
  <div class="card"><b>4. Реакция</b><p>При высоком риске вход блокируется до этапа 2FA.</p></div>
</div>
<h3>Как работает вход</h3>
<ol class="steps">
  <li>Пользователь вводит логин и пароль.</li>
  <li>Система анализирует IP, браузер, время входа и историю ошибок.</li>
  <li>Рассчитывается риск: низкий, средний или высокий.</li>
  <li>При низком/среднем риске пользователь вводит 2FA-код.</li>
  <li>При высоком риске вход запрещается, событие сохраняется в журнал.</li>
</ol>
"""
        self.send_html(render_page("Главная", body, user))

    def render_about(self, user):
        body = """
<h2>Модель риска</h2>
<p>На этой странице показано, какие признаки учитываются при входе и сколько баллов они добавляют.</p>
<div class="riskbox">
<b>Принцип:</b> если во время входа появляются подозрительные признаки, сумма баллов увеличивается. По итоговой сумме определяется уровень риска.
</div>
<h3>Факторы риска</h3>
<table>
<tr><th>Фактор</th><th>Когда добавляется</th><th>Баллы</th></tr>
<tr><td>Новый IP-адрес</td><td>IP отличается от прошлого успешного входа.</td><td>+20</td></tr>
<tr><td>Новый браузер или устройство</td><td>Браузер ещё не сохранён как доверенный.</td><td>+15</td></tr>
<tr><td>Ночное время</td><td>Вход выполняется до 06:00 или после 23:00.</td><td>+10</td></tr>
<tr><td>Неудачные попытки</td><td>Недавно были ошибки при вводе пароля или 2FA-кода.</td><td>+5 за каждую или +25 за 3+</td></tr>
<tr><td>Подозрительная сеть</td><td>Демо-признак для проверки высокого риска.</td><td>+30</td></tr>
</table>
<h3>Уровни риска</h3>
<table>
<tr><th>Баллы</th><th>Уровень</th><th>Что происходит</th></tr>
<tr><td>0–29</td><td><span class="badge low">низкий</span></td><td>Переход к вводу 2FA-кода.</td></tr>
<tr><td>30–59</td><td><span class="badge medium">средний</span></td><td>Переход к 2FA, попытка сохраняется в журнале.</td></tr>
<tr><td>60+</td><td><span class="badge high">высокий</span></td><td>Вход блокируется до этапа 2FA.</td></tr>
</table>
"""
        self.send_html(render_page("Модель риска", body, user))

    def render_demo(self, user):
        body = """
<h2>Демо-сценарии</h2>
<p>Несколько быстрых сценариев для проверки работы приложения.</p>
<table>
<tr><th>Сценарий</th><th>Что показать</th><th>Действие</th></tr>
<tr><td>Обычный вход</td><td>Пароль → анализ риска → 2FA → кабинет.</td><td><a class="btn" href="/login">Обычный вход</a></td></tr>
<tr><td>Подозрительный IP</td><td>Система добавляет баллы за демонстрационную внешнюю сеть.</td><td><a class="btn secondary" href="/login?demo_ip=8.8.8.8">Вход с demo_ip=8.8.8.8</a></td></tr>
<tr><td>Другой внешний IP</td><td>Альтернативный демо-адрес для высокого риска.</td><td><a class="btn secondary" href="/login?demo_ip=185.10.10.10">Вход с demo_ip=185.10.10.10</a></td></tr>
<tr><td>Журнал входов</td><td>Посмотреть сохранённые попытки входа.</td><td><a class="btn" href="/attempts">Открыть журнал</a></td></tr>
</table>
<h3>Порядок проверки</h3>
<ol class="steps">
  <li>Зарегистрировать пользователя и получить TOTP-секрет.</li>
  <li>Добавить секрет в Google Authenticator, Microsoft Authenticator или Aegis.</li>
  <li>Войти обычным способом.</li>
  <li>Открыть кабинет и посмотреть таблицу балльной модели.</li>
  <li>Выйти из аккаунта.</li>
  <li>Сделать 1–2 неправильные попытки входа, чтобы появились баллы за ошибки.</li>
  <li>Открыть вход через <code>/login?demo_ip=8.8.8.8</code>.</li>
  <li>Проверить блокировку высокого риска и запись в журнале.</li>
</ol>
<div class="riskbox"><b>Важно:</b> высокий риск обычно получается при сумме факторов, например: новый браузер (+15), новый IP (+20), демо-подозрительная сеть (+30), ошибки входа (+5 или +25).</div>
"""
        self.send_html(render_page("Демо-сценарии", body, user))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        user = self.current_user()

        if path == "/":
            self.render_home(user)
        elif path == "/about":
            self.render_about(user)
        elif path == "/demo":
            self.render_demo(user)
        elif path == "/register":
            body = """
<h2>Регистрация</h2>
<p>После регистрации система создаст секретный ключ для настройки второго фактора.</p>
<form method="post">
<label>Логин</label><input name="username" required>
<label>Email</label><input name="email" type="email" required>
<label>Пароль</label><input name="password" type="password" required>
<button>Создать аккаунт</button>
</form>
"""
            self.send_html(render_page("Регистрация", body, user))
        elif path == "/login":
            demo = e(parsed.query)
            action = "/login" + ("?" + demo if demo else "")
            body = f"""
<h2>Вход</h2>
<p>Сначала система проверит пароль, затем рассчитает риск входа.</p>
<form method="post" action="{action}">
<label>Логин</label><input name="username" required>
<label>Пароль</label><input name="password" type="password" required>
<button>Продолжить</button>
</form>
<p class="small">Для проверки высокого риска можно использовать <code>/login?demo_ip=8.8.8.8</code>.</p>
"""
            self.send_html(render_page("Вход", body, user))
        elif path == "/verify":
            sid = unsign(self.parse_cookies().get(SESSION_COOKIE, "") or "")
            pending = SESSIONS.get(sid, {}).get("pending_login") if sid else None
            if not pending:
                self.redirect("/login")
                return
            factors_html = ""
            if pending.get("factors"):
                factors_html = "<ul>" + "".join([f"<li>{e(name)} <b>+{points}</b></li>" for name, points in pending["factors"]]) + "</ul>"
            else:
                factors_html = "<p>Подозрительных признаков не обнаружено.</p>"
            body = f"""
<h2>Подтверждение 2FA</h2>
<div class="cards">
  <div class="card"><b>Уровень риска</b><div class="num">{status_badge(pending['level'])}</div></div>
  <div class="card"><b>Баллы риска</b><div class="num">{pending['score']}</div></div>
  <div class="card"><b>Решение</b><p>{e(pending['decision'])}</p></div>
</div>
<h3>Обнаруженные признаки</h3>
{factors_html}
<form method="post">
<label>6-значный TOTP-код</label><input name="code" inputmode="numeric" required>
<button>Подтвердить вход</button>
</form>
"""
            self.send_html(render_page("2FA", body, user))
        elif path == "/dashboard":
            if not user:
                self.redirect("/login")
                return
            stats = user_stats(user["username"])
            last = stats["last"]
            last_html = "Нет записей" if not last else f"{e(last['login_time'])}, IP: <code>{e(last['ip_address'])}</code>, риск: {status_badge(last['risk_level'])}"
            body = f"""
<h2>Кабинет пользователя</h2>
<p class="ok">Вы успешно вошли в систему.</p>
<div class="cards">
  <div class="card"><b>Пользователь</b><p>{e(user['username'])}</p><p class="small">{e(user['email'])}</p></div>
  <div class="card"><b>Всего попыток</b><div class="num">{stats['total']}</div></div>
  <div class="card"><b>Успешных входов</b><div class="num">{stats['success']}</div></div>
  <div class="card"><b>Подозрительных</b><div class="num">{stats['suspicious']}</div></div>
  <div class="card"><b>Заблокировано</b><div class="num">{stats['blocked']}</div></div>
</div>
<h3>Последняя попытка</h3>
<p>{last_html}</p>
<h3>Балльная модель риска</h3>
<table><tr><th>Признак</th><th>Баллы</th></tr><tr><td>Новый IP-адрес</td><td>+20</td></tr><tr><td>Новое устройство/браузер</td><td>+15</td></tr><tr><td>Вход ночью</td><td>+10</td></tr><tr><td>1–2 неудачные попытки</td><td>+5 за каждую</td></tr><tr><td>3+ неудачные попытки</td><td>+25</td></tr><tr><td>Демо-подозрительная внешняя сеть</td><td>+30</td></tr></table>
<h3>Реакция системы</h3>
<table><tr><th>Баллы</th><th>Уровень</th><th>Действие</th></tr><tr><td>0–29</td><td>{status_badge('низкий')}</td><td>Переход к 2FA</td></tr><tr><td>30–59</td><td>{status_badge('средний')}</td><td>Переход к 2FA + запись как подозрительная попытка</td></tr><tr><td>60+</td><td>{status_badge('высокий')}</td><td>Вход запрещён, пользователь не допускается к 2FA</td></tr></table>
"""
            self.send_html(render_page("Кабинет", body, user))
        elif path == "/attempts":
            if not user:
                self.redirect("/login")
                return
            with db() as conn:
                rows = conn.execute("SELECT * FROM login_attempts WHERE username = ? ORDER BY id DESC LIMIT 100", (user["username"],)).fetchall()
            if rows:
                trs = "".join([
                    f"<tr><td>{e(r['login_time'])}</td><td><code>{e(r['ip_address'])}</code></td><td>{result_badge(r)}</td><td>{e(r['risk_score'])}</td><td>{status_badge(r['risk_level'])}</td><td>{e(r['decision'])}</td><td>{e(r['reason'])}</td></tr>"
                    for r in rows
                ])
            else:
                trs = "<tr><td colspan='7'>Пока нет записей.</td></tr>"
            body = f"""
<h2>Журнал входов</h2>
<p>Здесь сохраняются все попытки авторизации: успешные, неуспешные и заблокированные.</p>
<p><a class="btn" href="/export">Скачать CSV-отчёт</a></p>
<table><tr><th>Время</th><th>IP</th><th>Результат</th><th>Баллы</th><th>Риск</th><th>Решение</th><th>Причины</th></tr>{trs}</table>
"""
            self.send_html(render_page("Журнал", body, user))
        elif path == "/export":
            if not user:
                self.redirect("/login")
                return
            with db() as conn:
                rows = conn.execute("SELECT login_time, username, ip_address, success, risk_score, risk_level, decision, reason FROM login_attempts WHERE username = ? ORDER BY id DESC", (user["username"],)).fetchall()
            out = io.StringIO()
            writer = csv.writer(out, delimiter=";")
            writer.writerow(["Время", "Пользователь", "IP", "Успех", "Баллы риска", "Уровень риска", "Решение", "Причина"])
            for r in rows:
                writer.writerow([r["login_time"], r["username"], r["ip_address"], "да" if r["success"] else "нет", r["risk_score"], r["risk_level"], r["decision"], r["reason"]])
            self.send_text(out.getvalue(), "riskauth_login_report.csv")
        elif path == "/logout":
            sid = unsign(self.parse_cookies().get(SESSION_COOKIE, "") or "")
            if sid:
                SESSIONS.pop(sid, None)
            self.redirect("/", f"{SESSION_COOKIE}=; Max-Age=0; Path=/")
        else:
            self.send_html(render_page("404", "<h2>Страница не найдена</h2>", user), 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        data = self.form_data()
        ua = self.headers.get("User-Agent", "unknown")
        ip = self.get_ip(parsed.query)
        user = self.current_user()

        if path == "/register":
            username = data.get("username", "").strip()
            email = data.get("email", "").strip()
            password = data.get("password", "")
            if not username or not email or not password:
                self.send_html(render_page("Регистрация", "<p class='bad'>Заполните все поля.</p>", user), 400)
                return
            secret = new_totp_secret()
            try:
                with db() as conn:
                    conn.execute(
                        "INSERT INTO users(username,email,password_hash,totp_secret,created_at) VALUES(?,?,?,?,?)",
                        (username, email, password_hash(password), secret, now_str()),
                    )
            except sqlite3.IntegrityError:
                self.send_html(render_page("Регистрация", "<p class='bad'>Такой логин уже существует.</p><p><a href='/register'>Назад</a></p>", user), 400)
                return
            issuer = urllib.parse.quote(APP_NAME)
            label = urllib.parse.quote(f"{APP_NAME}:{username}")
            uri = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6&period=30"
            body = f"""
<h2>Настройка второго фактора</h2>
<p>Добавьте аккаунт в Google Authenticator, Microsoft Authenticator или Aegis вручную.</p>
<div class="cards">
  <div class="card"><b>Секретный ключ</b><p><code>{e(secret)}</code></p></div>
  <div class="card"><b>Тип кода</b><p>TOTP, 6 цифр, период 30 секунд.</p></div>
</div>
<h3>URI для приложения-аутентификатора</h3>
<p><code>{e(uri)}</code></p>
<p class="small">В учебном прототипе QR-код не используется, чтобы проект запускался без внешних библиотек.</p>
<p><a class="btn" href="/login">Перейти ко входу</a></p>
"""
            self.send_html(render_page("Настройка 2FA", body, None))
        elif path == "/login":
            username = data.get("username", "").strip()
            password = data.get("password", "")
            u = get_user(username)
            score, level, decision, reason, factors = calculate_risk(u, username, ip, ua)
            if not u or not check_password(password, u["password_hash"]):
                log_attempt(u["id"] if u else None, username, ip, ua, False, score, level, "отказ: неверный логин или пароль", "неверный логин или пароль; " + reason)
                body = "<h2>Ошибка входа</h2><p class='bad'>Неверный логин или пароль.</p><p><a class='btn' href='/login'>Попробовать ещё раз</a></p>"
                self.send_html(render_page("Ошибка входа", body, None), 401)
                return
            if level == "высокий":
                log_attempt(u["id"], username, ip, ua, False, score, level, decision, "вход заблокирован из-за высокого риска; " + reason)
                factors_html = "<ul>" + "".join([f"<li>{e(name)} <b>+{points}</b></li>" for name, points in factors]) + "</ul>"
                body = f"""
<h2>Вход запрещён</h2>
<p class="bad">Очень подозрительный вход. Система заблокировала попытку авторизации.</p>
<div class="cards">
  <div class="card"><b>Баллы риска</b><div class="num">{score}</div></div>
  <div class="card"><b>Уровень</b><div class="num">{status_badge(level)}</div></div>
  <div class="card"><b>Решение</b><p>{e(decision)}</p></div>
</div>
<h3>Причины блокировки</h3>
{factors_html}
<p>Пользователь не допускается к этапу 2FA, потому что риск слишком высокий.</p>
<p><a class="btn" href="/login">Назад ко входу</a> <a class="btn secondary" href="/demo">Демо-сценарии</a></p>
"""
                self.send_html(render_page("Блокировка", body, None), 403)
                return
            sid = secrets.token_urlsafe(24)
            SESSIONS[sid] = {"pending_login": {"user_id": u["id"], "username": username, "ip": ip, "ua": ua, "score": score, "level": level, "decision": decision, "reason": reason, "factors": factors}}
            self.redirect("/verify", f"{SESSION_COOKIE}={sign(sid)}; HttpOnly; Path=/; SameSite=Lax")
        elif path == "/verify":
            sid = unsign(self.parse_cookies().get(SESSION_COOKIE, "") or "")
            pending = SESSIONS.get(sid, {}).get("pending_login") if sid else None
            if not pending:
                self.redirect("/login")
                return
            with db() as conn:
                u = conn.execute("SELECT * FROM users WHERE id = ?", (pending["user_id"],)).fetchone()
            code = data.get("code", "")
            if not verify_totp(u["totp_secret"], code):
                log_attempt(u["id"], u["username"], pending["ip"], pending["ua"], False, pending["score"], pending["level"], "отказ: неверный 2FA-код", "неверный 2FA-код; " + pending["reason"])
                body = "<h2>Ошибка 2FA</h2><p class='bad'>Неверный код.</p><p><a class='btn' href='/verify'>Попробовать снова</a></p>"
                self.send_html(render_page("Ошибка 2FA", body, None), 401)
                return
            log_attempt(u["id"], u["username"], pending["ip"], pending["ua"], True, pending["score"], pending["level"], pending["decision"], pending["reason"])
            remember_device(u["id"], pending["ip"], pending["ua"])
            SESSIONS[sid] = {"user_id": u["id"]}
            self.redirect("/dashboard", f"{SESSION_COOKIE}={sign(sid)}; HttpOnly; Path=/; SameSite=Lax")
        else:
            self.send_html(render_page("404", "<h2>Страница не найдена</h2>", user), 404)


if __name__ == "__main__":
    init_db()
    print(f"Сервер запущен: http://{HOST}:{PORT}")
    print("Для остановки нажмите Ctrl+C")
    HTTPServer((HOST, PORT), Handler).serve_forever()

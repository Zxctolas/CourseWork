from http.server import HTTPServer, BaseHTTPRequestHandler

APP_NAME = "RiskAuth 2FA"
HOST = "127.0.0.1"
PORT = 5000


def page(title, body):
    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f6f8; margin: 0; color: #1f2937; }}
        header {{ background: #111827; color: white; padding: 22px 32px; }}
        main {{ max-width: 900px; margin: 30px auto; background: white; padding: 28px; border-radius: 14px; }}
        a {{ color: #2563eb; font-weight: bold; }}
    </style>
</head>
<body>
<header><h1>{APP_NAME}</h1></header>
<main>{body}</main>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def send_html(self, text, status=200):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            body = """
            <h2>Главная страница</h2>
            <p>Заготовка приложения для регистрации, входа и двухфакторной аутентификации.</p>
            <p><a href='/register'>Регистрация</a> | <a href='/login'>Вход</a></p>
            """
            self.send_html(page("Главная", body))
        elif self.path == "/register":
            self.send_html(page("Регистрация", "<h2>Регистрация</h2><p>Страница будет добавлена позже.</p>"))
        elif self.path == "/login":
            self.send_html(page("Вход", "<h2>Вход</h2><p>Страница будет добавлена позже.</p>"))
        else:
            self.send_html(page("404", "<h2>Страница не найдена</h2>"), 404)


if __name__ == "__main__":
    print(f"Сервер запущен: http://{HOST}:{PORT}")
    HTTPServer((HOST, PORT), Handler).serve_forever()

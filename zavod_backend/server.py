"""
Завод Нева — Backend
Запуск: python server.py
"""
import hashlib, hmac, json, os, sqlite3, time, base64, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError
import ssl
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# Сначала пытаемся взять из .env файла рядом
_env_path = os.path.join(os.path.dirname(__file__), "server.env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ[_k.strip()] = _v.strip().strip("'\"")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN")
PIN_CODE  = os.environ.get("PIN_CODE",  "1234")
PORT      = int(os.environ.get("PORT",  "8000"))
DB_PATH   = os.environ.get("DB_PATH",  "zavod.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS shared (
        key     TEXT PRIMARY KEY,
        value   TEXT NOT NULL,
        updated INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS proposals (
        id      TEXT NOT NULL,
        user_id TEXT NOT NULL,
        data    TEXT NOT NULL,
        updated INTEGER NOT NULL,
        PRIMARY KEY(id, user_id)
    );
    """)
    c.commit(); c.close()
    print("DB ready:", DB_PATH)

init_db()

def verify_tg(init_data: str):
    try:
        params = {}
        for part in init_data.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v
        user_str = params.get("user", "")
        if not user_str: return None
        from urllib.parse import unquote
        return json.loads(unquote(user_str))
    except Exception as e:
        print(f"verify_tg error: {e}")
        return None

def get_user_id(headers, body):
    init_data = headers.get("x-tg-initdata", "") or body.get("init_data", "")
    print(f"[AUTH] headers keys: {list(headers.keys())}")
    print(f"[AUTH] init_data present: {bool(init_data)}, len={len(init_data)}")
    print(f"[AUTH] body keys: {list(body.keys())}")
    if init_data:
        user = verify_tg(init_data)
        print(f"[AUTH] verify_tg result: {user}")
        if user: return f"tg_{user['id']}", user
    pin = str(headers.get("x-pin", "") or body.get("pin", "") or "")
    print(f"[AUTH] pin: '{pin}', expected: '{PIN_CODE}'")
    if pin and pin != "None" and pin == PIN_CODE:
        name = body.get("username", "browser")
        return f"web_{name}", {"first_name": name}
    # Если нет авторизации но есть username — разрешаем как гость
    username = body.get("username", "")
    if username:
        # Используем username как стабильный ID (это device_id из localStorage)
        uid = f"guest_{username}"
        print(f"[AUTH] guest access for: {uid}")
        return uid, {"first_name": username}
    return None, None

def send_telegram_document(chat_id, pdf_bytes, filename, caption=""):
    """Отправляет PDF файл в Telegram чат"""
    boundary = "----FormBoundary" + str(int(time.time()))
    
    body_parts = []
    # chat_id
    body_parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}')
    # caption
    if caption:
        body_parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="caption"\r\n\r\n{caption}')
    # document
    body_parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\n'
        f'Content-Type: application/pdf\r\n\r\n'
    )
    
    body = '\r\n'.join(body_parts).encode() + pdf_bytes + f'\r\n--{boundary}--\r\n'.encode()
    
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    req = Request(url, data=body, headers={
        'Content-Type': f'multipart/form-data; boundary={boundary}'
    })
    try:
        resp = urlopen(req, timeout=30, context=_ssl_ctx)
        return json.loads(resp.read())
    except Exception as e:
        print(f"Telegram send error: {e}")
        return None

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,X-TG-InitData,X-Pin,ngrok-skip-browser-warning,Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS,PUT")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,X-TG-InitData,X-Pin,ngrok-skip-browser-warning,Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS,PUT")
        self.end_headers()

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length: return json.loads(self.rfile.read(length))
        return {}

    def get_headers(self):
        return {k.lower(): v for k, v in self.headers.items()}

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")
        headers = self.get_headers()

        if path == "/health":
            return self.send_json({"ok": True, "time": int(time.time())})

        if path == "/shared":
            uid, _ = get_user_id(headers, {})
            if not uid: return self.send_json({"error": "auth"}, 401)
            c = db()
            catalog = c.execute("SELECT value FROM shared WHERE key='catalog'").fetchone()
            schemes = c.execute("SELECT value FROM shared WHERE key='schemes'").fetchone()
            c.close()
            return self.send_json({
                "catalog": json.loads(catalog["value"]) if catalog else [],
                "schemes": json.loads(schemes["value"]) if schemes else [],
            })

        if path == "/proposals":
            uid, _ = get_user_id(headers, {})
            if not uid: return self.send_json({"error": "auth"}, 401)
            c = db()
            rows = c.execute("SELECT data FROM proposals WHERE user_id=? ORDER BY updated DESC", (uid,)).fetchall()
            c.close()
            return self.send_json([json.loads(r["data"]) for r in rows])

        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        headers = self.get_headers()
        body = self.read_body()

        # ── Отправка PDF в Telegram ────────────────────────────────────────────
        if path == "/send-pdf":
            uid, user = get_user_id(headers, body)
            if not uid: return self.send_json({"error": "auth"}, 401)
            
            # Получаем данные
            pdf_b64  = body.get("pdf_base64", "")
            filename = body.get("filename", "КП.pdf")
            caption  = body.get("caption", "")
            chat_id  = body.get("chat_id")
            
            if not pdf_b64 or not chat_id:
                return self.send_json({"error": "pdf_base64 and chat_id required"}, 400)
            
            # Декодируем base64
            try:
                # Убираем префикс data:application/pdf;base64,
                if "," in pdf_b64:
                    pdf_b64 = pdf_b64.split(",", 1)[1]
                pdf_bytes = base64.b64decode(pdf_b64)
            except Exception as e:
                return self.send_json({"error": f"invalid base64: {e}"}, 400)
            
            # Отправляем через Telegram Bot API
            result = send_telegram_document(chat_id, pdf_bytes, filename, caption)
            if result and result.get("ok"):
                return self.send_json({"ok": True, "message_id": result["result"]["message_id"]})
            else:
                return self.send_json({"error": "telegram send failed", "detail": str(result)}, 500)

        uid, user = get_user_id(headers, body)
        if not uid: return self.send_json({"error": "auth"}, 401)

        if path == "/sync":
            c = db()
            # Каталог — принимаем только если клиент отправил непустой
            existing_catalog = c.execute("SELECT value FROM shared WHERE key='catalog'").fetchone()
            client_catalog = body.get("catalog", [])
            server_count = len(json.loads(existing_catalog["value"])) if existing_catalog else 0
            client_count = len(client_catalog)
            if client_catalog:
                c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                    ("catalog", json.dumps(client_catalog, ensure_ascii=False), int(time.time())))
                c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                    ("catalog_updated", json.dumps(int(time.time())), int(time.time())))
                print(f"[SYNC] Catalog updated: {client_count} items (was {server_count})")
            else:
                print(f"[SYNC] Catalog: returning server version ({server_count} items)")
            existing_schemes = c.execute("SELECT value FROM shared WHERE key='schemes'").fetchone()
            client_schemes = body.get("schemes", [])
            server_schemes_count = len(json.loads(existing_schemes["value"])) if existing_schemes else 0
            if client_schemes:
                c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                    ("schemes", json.dumps(client_schemes, ensure_ascii=False), int(time.time())))
                print(f"[SYNC] Schemes updated: {len(client_schemes)} items (was {server_schemes_count})")
            else:
                print(f"[SYNC] Schemes: returning server version ({server_schemes_count} items)")
            # Proposals — теперь тоже в shared (единый список для всех устройств)
            existing_proposals = c.execute("SELECT value FROM shared WHERE key='proposals'").fetchone()
            client_proposals = body.get("proposals", [])
            server_proposals_count = len(json.loads(existing_proposals["value"])) if existing_proposals else 0
            if client_proposals:
                c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                    ("proposals", json.dumps(client_proposals, ensure_ascii=False), int(time.time())))
                c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                    ("proposals_updated", json.dumps(int(time.time())), int(time.time())))
                print(f"[SYNC] Proposals updated: {len(client_proposals)} items (was {server_proposals_count})")
            else:
                print(f"[SYNC] Proposals: returning server version ({server_proposals_count} items)")
            c.commit()
            catalog  = c.execute("SELECT value FROM shared WHERE key='catalog'").fetchone()
            schemes  = c.execute("SELECT value FROM shared WHERE key='schemes'").fetchone()
            proposals = c.execute("SELECT value FROM shared WHERE key='proposals'").fetchone()
            c.close()
            return self.send_json({
                "ok": True,
                "catalog":   json.loads(catalog["value"]) if catalog else [],
                "schemes":   json.loads(schemes["value"]) if schemes else [],
                "proposals": json.loads(proposals["value"]) if proposals else [],
                "user_id":   uid,
            })

        if path == "/shared/catalog":
            c = db()
            c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                ("catalog", json.dumps(body.get("data", []), ensure_ascii=False), int(time.time())))
            c.commit(); c.close()
            return self.send_json({"ok": True})

        if path == "/shared/schemes":
            c = db()
            c.execute("INSERT OR REPLACE INTO shared VALUES (?,?,?)",
                ("schemes", json.dumps(body.get("data", []), ensure_ascii=False), int(time.time())))
            c.commit(); c.close()
            return self.send_json({"ok": True})

        self.send_json({"error": "not found"}, 404)

if __name__ == "__main__":
    print(f"Завод Нева Backend запускается на порту {PORT}...")
    print(f"Health check: http://localhost:{PORT}/health")
    print(f"PIN для браузера: {PIN_CODE}")
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)

    # Фоновый polling команд Telegram (для /paint и других)
    import signal as _signal
    _stop_polling = threading.Event()

    def _poll_commands():
        """Периодически проверяет новые сообщения через getUpdates и отвечает на команды"""
        offset = 0
        PAINT_URL = "https://russel731.github.io/paint-calc/"
        while not _stop_polling.is_set():
            try:
                url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?offset={offset}&timeout=30"
                req = urlopen(url, timeout=35, context=_ssl_ctx)
                updates = json.loads(req.read()).get("result", [])
                for upd in updates:
                    offset = upd["update_id"] + 1
                    msg = upd.get("message") or upd.get("callback_query", {}).get("message")
                    if not msg:
                        continue
                    chat_id = msg["chat"]["id"]
                    text = (msg.get("text") or "").strip().lower()
                    if text in ("/start", "/menu"):
                        kb = json.dumps({
                            "inline_keyboard": [[
                                {"text": "🎨 Расчёт площади покраски", "web_app": {"url": PAINT_URL}},
                                {"text": "📄 Сделать КП", "web_app": {"url": "https://russel731.github.io/zavod.neva/"}}
                            ]]
                        })
                        reply_url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
                        data = json.dumps({
                            "chat_id": chat_id,
                            "text": "Выберите калькулятор:",
                            "reply_markup": kb
                        }).encode()
                        req2 = Request(reply_url, data=data, headers={"Content-Type": "application/json"})
                        urlopen(req2, timeout=10, context=_ssl_ctx)
                    elif text == "/paint":
                        kb = json.dumps({
                            "inline_keyboard": [[
                                {"text": "🎨 Открыть калькулятор", "web_app": {"url": PAINT_URL}}
                            ]]
                        })
                        reply_url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
                        data = json.dumps({
                            "chat_id": chat_id,
                            "text": "Калькулятор площади покраски металлоконструкций",
                            "reply_markup": kb
                        }).encode()
                        req2 = Request(reply_url, data=data, headers={"Content-Type": "application/json"})
                        urlopen(req2, timeout=10, context=_ssl_ctx)
            except Exception as e:
                if not _stop_polling.is_set():
                    print(f"[PollBot] error: {e}")
            if not _stop_polling.is_set():
                _stop_polling.wait(1)

    poll_thread = threading.Thread(target=_poll_commands, daemon=True)
    poll_thread.start()

    # Регистрируем команду /paint в Bot API
    try:
        cmds_url = f"https://api.telegram.org/bot{BOT_TOKEN}/setMyCommands"
        data = json.dumps({"commands": [
            {"command": "paint", "description": "🎨 Калькулятор площади покраски"},
        ]}).encode()
        req_cmds = Request(cmds_url, data=data, headers={"Content-Type": "application/json"})
        urlopen(req_cmds, timeout=10, context=_ssl_ctx)
        print("[PollBot] Command /paint registered")
    except Exception as e:
        print(f"[PollBot] Command registration error: {e}")

    print("[PollBot] Started polling Telegram commands")
    httpd.serve_forever()
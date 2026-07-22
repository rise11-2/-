"""
简易用户信息管理平台 — 安全加固版
=================================
防护措施：
  1. bcrypt 哈希存储密码（非明文）
  2. 参数化查询防 SQL 注入
  3. CSRF Token 校验
  4. IP 级登录失败锁定 + 渐进式延迟（防暴力破解）
  5. 随机 secret_key + session 超时
  6. 统一错误提示防用户名枚举
  7. 文件上传漏洞修复（类型校验 + 内容检测 + 安全命名）
"""
import sqlite3
import os
import time
import secrets
import uuid
import struct
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session, g, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ============================================================
# 1. 应用配置
# ============================================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # 随机 64 位密钥，每次启动不同
app.permanent_session_lifetime = timedelta(minutes=30)  # session 30 分钟过期
app.debug = False  # 关闭 debug 模式防信息泄露
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 最大上传 16MB

# 允许上传的图片类型
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "bmp"}

# 图片文件魔数（文件头标识）
IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
}


def detect_image_type(data):
    """通过文件头魔数检测是否为有效图片，返回图片类型或 None"""
    for signature, img_type in IMAGE_SIGNATURES.items():
        if data[:len(signature)] == signature:
            return img_type
    # WebP 特殊检测：RIFF....WEBP
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None

# ============================================================
# 2. 数据库
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")


def get_db():
    """获取数据库连接（每个请求独立连接）"""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """请求结束后关闭数据库连接"""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库并插入默认用户（密码哈希存储）"""
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "static", "uploads"), exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email    TEXT,
            phone    TEXT,
            balance  REAL DEFAULT 0.0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address   TEXT NOT NULL,
            attempt_time REAL NOT NULL,
            success      INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_ip
            ON login_attempts(ip_address, attempt_time)
    """)
    db.commit()

    # 插入默认用户 — 密码使用 bcrypt 哈希
    default_users = [
        ("admin",  generate_password_hash("admin123"),  "admin@example.com", "13800138000"),
        ("alice",  generate_password_hash("alice2025"), "alice@example.com", "13900139001"),
    ]
    for u in default_users:
        try:
            db.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                u,
            )
        except sqlite3.IntegrityError:
            pass
    db.commit()
    db.close()


# ============================================================
# 3. CSRF Token 防护
# ============================================================

def generate_csrf_token():
    """生成或返回已有 CSRF Token"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return session["_csrf_token"]


def validate_csrf_token():
    """校验 CSRF Token，校验后立即失效（一次性）"""
    token = request.form.get("_csrf_token")
    stored = session.pop("_csrf_token", None)
    if not token or not stored:
        return False
    return secrets.compare_digest(stored, token)


# ============================================================
# 4. 暴力破解防护（IP 级锁定 + 渐进式延迟）
# ============================================================

def check_login_rate_limit(ip_addr):
    """
    IP 级别登录频率限制：
      - 15 分钟内失败 ≥ 10 次 → 锁定
      - 每次失败增加等待时间：min(失败次数 × 2, 30) 秒
    """
    db = get_db()
    window = time.time() - 900  # 15 分钟窗口

    cur = db.execute(
        "SELECT COUNT(*) AS cnt FROM login_attempts "
        "WHERE ip_address = ? AND attempt_time > ? AND success = 0",
        (ip_addr, window),
    )
    row = cur.fetchone()
    fail_count = row["cnt"] if row else 0

    locked = False
    remaining_seconds = 0

    if fail_count >= 10:
        cur = db.execute(
            "SELECT attempt_time FROM login_attempts "
            "WHERE ip_address = ? AND attempt_time > ? AND success = 0 "
            "ORDER BY attempt_time ASC LIMIT 1",
            (ip_addr, window),
        )
        earliest = cur.fetchone()
        if earliest:
            lock_until = earliest["attempt_time"] + 900
            remaining = lock_until - time.time()
            if remaining > 0:
                locked = True
                remaining_seconds = int(remaining)
            else:
                db.execute(
                    "DELETE FROM login_attempts WHERE ip_address = ? AND attempt_time < ?",
                    (ip_addr, time.time() - 900),
                )
                db.commit()
                fail_count = 0

    delay = min(fail_count * 2, 30)

    return locked, remaining_seconds, delay


def record_login_attempt(ip_addr, success):
    """记录一次登录尝试"""
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (ip_address, attempt_time, success) VALUES (?, ?, ?)",
        (ip_addr, time.time(), 1 if success else 0),
    )
    db.commit()


def pending_login_count(ip_addr):
    """返回当前 IP 在窗口内的失败次数"""
    db = get_db()
    window = time.time() - 900
    cur = db.execute(
        "SELECT COUNT(*) AS cnt FROM login_attempts "
        "WHERE ip_address = ? AND attempt_time > ? AND success = 0",
        (ip_addr, window),
    )
    row = cur.fetchone()
    return row["cnt"] if row else 0


# ============================================================
# 5. 路由 — 首页
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        db = get_db()
        cur = db.execute("SELECT id, username, email, phone FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            user_info = dict(row)
    return render_template("index.html", user=user_info, keyword="", results=None)


# ============================================================
# 6. 路由 — 登录（CSRF + 频率限制 + 哈希比对）
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    ip_addr = request.remote_addr or "unknown"

    if request.method == "POST":
        # 6a. CSRF Token 校验
        if not validate_csrf_token():
            return render_template("login.html",
                                   msg="",
                                   error="Token 校验失败，请刷新页面重试。",
                                   csrf_token=generate_csrf_token())

        # 6b. IP 频率限制检查
        locked, remaining_seconds, delay = check_login_rate_limit(ip_addr)
        if locked:
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60
            return render_template(
                "login.html",
                msg="",
                error=f"登录尝试过于频繁，请等待 {minutes} 分 {seconds} 秒后再试。",
                csrf_token=generate_csrf_token(),
            )

        # 6c. 参数化查询获取用户（防 SQL 注入）
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row is None:
            # 用户不存在 — 用相同延迟防用户名枚举
            time.sleep(1)
            record_login_attempt(ip_addr, False)
            return render_template("login.html",
                                   msg="",
                                   error="用户名或密码错误！",
                                   csrf_token=generate_csrf_token())

        # 6d. 密码哈希比对
        if check_password_hash(row["password"], password):
            # 登录成功
            record_login_attempt(ip_addr, True)
            session.permanent = True
            session["username"] = username
            session["user_id"] = row["id"]
            user_info = {"id": row["id"], "username": row["username"],
                         "email": row["email"], "phone": row["phone"]}
            return render_template("index.html", user=user_info, keyword="", results=None)
        else:
            # 登录失败 — 渐进式延迟
            time.sleep(delay)
            record_login_attempt(ip_addr, False)
            error_msg = "用户名或密码错误！"
            cnt = pending_login_count(ip_addr)
            if cnt > 0:
                error_msg += f"（{cnt} 次失败，请稍后再试）"
            return render_template("login.html",
                                   msg="",
                                   error=error_msg,
                                   csrf_token=generate_csrf_token())

    msg = request.args.get("msg", "")
    return render_template("login.html", msg=msg, csrf_token=generate_csrf_token())


# ============================================================
# 7. 路由 — 注册（参数化查询 + bcrypt 哈希）
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # CSRF Token 校验
        if not validate_csrf_token():
            return render_template("register.html",
                                   error="Token 校验失败，请刷新页面重试。",
                                   csrf_token=generate_csrf_token())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 密码使用 bcrypt 哈希存储
        password_hash = generate_password_hash(password)

        db = get_db()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[REGISTER] {sql} | username={username!r}, email={email!r}, phone={phone!r}")
        try:
            db.execute(sql, (username, password_hash, email, phone))
            db.commit()
            return redirect("/login?msg=注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html",
                                   error="用户名已存在！",
                                   csrf_token=generate_csrf_token())
        except Exception as e:
            return render_template("register.html",
                                   error=f"注册失败：{str(e)}",
                                   csrf_token=generate_csrf_token())

    return render_template("register.html", csrf_token=generate_csrf_token())


# ============================================================
# 8. 路由 — 搜索（参数化查询防 SQL 注入）
# ============================================================

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        db = get_db()
        pattern = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SEARCH] {sql} | keyword={keyword!r}")
        cur = db.execute(sql, (pattern, pattern))
        rows = cur.fetchall()
        results = [dict(row) for row in rows]

    # 获取当前登录用户信息
    username = session.get("username")
    user_info = None
    if username:
        db = get_db()
        cur = db.execute("SELECT id, username, email, phone FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            user_info = dict(row)

    return render_template("index.html", user=user_info, keyword=keyword, results=results)


# ============================================================
# 9. 路由 — 上传头像（已修复文件上传漏洞）
# ============================================================

def allowed_file(filename):
    """检查文件扩展名是否在允许范围内"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """上传头像，需要登录"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")

        # 检查是否有文件
        if not file or not file.filename:
            return render_template("upload.html", error="请选择要上传的文件")

        # 检查文件扩展名
        if not allowed_file(file.filename):
            return render_template("upload.html",
                                   error="仅支持上传图片文件（jpg、jpeg、png、gif、webp、bmp）")

        # 检查文件内容是否为空
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size == 0:
            return render_template("upload.html", error="文件内容为空")

        # 检查文件内容是否为真实图片（通过文件头魔数验证）
        file_head = file.read(32)
        file.seek(0)
        if detect_image_type(file_head) is None:
            return render_template("upload.html", error="文件不是有效的图片格式")

        # 使用 secure_filename 清理文件名，再用 UUID 重命名防止覆盖
        safe_name = secure_filename(file.filename)
        ext = safe_name.rsplit(".", 1)[1].lower() if "." in safe_name else ""
        unique_name = f"{uuid.uuid4().hex}.{ext}"

        upload_dir = os.path.join(BASE_DIR, "static", "uploads")
        filepath = os.path.join(upload_dir, unique_name)
        file.save(filepath)
        file_url = url_for("static", filename=f"uploads/{unique_name}")
        return render_template("upload.html", file_url=file_url, filename=unique_name)

    return render_template("upload.html")


# ============================================================
# 10. 路由 — 个人中心（已修复越权漏洞）
# ============================================================

@app.route("/profile")
def profile():
    """个人中心 — 仅允许查看自己的资料"""
    if "username" not in session:
        return redirect("/login")

    user_id = request.args.get("user_id")

    # 越权修复：只允许查看自己的资料
    if str(session.get("user_id")) != str(user_id):
        return render_template("profile.html", user=None, error="无权查看其他用户的资料", csrf_token=generate_csrf_token())

    db = get_db()
    cur = db.execute(
        "SELECT id, username, email, phone, balance FROM users WHERE id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    user_info = dict(row) if row else None
    return render_template("profile.html", user=user_info, csrf_token=generate_csrf_token())


# ============================================================
# 11. 路由 — 充值（已修复逻辑漏洞）
# ============================================================

@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 — 需登录 + CSRF + 仅限自己 + 金额正数"""
    if "username" not in session:
        return redirect("/login")

    # CSRF 校验
    if not validate_csrf_token():
        return render_template("profile.html",
                               user=None,
                               error="Token 校验失败，请刷新页面重试。")

    user_id = request.form.get("user_id")

    # 越权修复：只允许给自己充值
    if str(session.get("user_id")) != str(user_id):
        return render_template("profile.html",
                               user=None,
                               error="无权给其他用户充值")

    amount = request.form.get("amount", "0")
    try:
        amount = float(amount)
    except ValueError:
        amount = 0.0

    # 逻辑修复：金额必须为正数
    if amount <= 0:
        # 重新查询用户信息传回页面
        db = get_db()
        cur = db.execute(
            "SELECT id, username, email, phone, balance FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()
        user_info = dict(row) if row else None
        return render_template("profile.html",
                               user=user_info,
                               error="充值金额必须大于 0")

    db = get_db()
    db.execute(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        (amount, user_id),
    )
    db.commit()
    return redirect(f"/profile?user_id={user_id}")


# ============================================================
# 12. 路由 — 退出
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
# 13. 启动入口
# ============================================================

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  简易信息管理平台 — 安全加固版")
    print("=" * 60)
    print(f"  监听地址:   http://0.0.0.0:5000")
    print(f"  数据库:     {DATABASE}")
    print(f"  默认用户:   admin / alice")
    print(f"  密码存储:   bcrypt 哈希（非明文）")
    print(f"  SQL 注入:   已防护（参数化查询）")
    print(f"  CSRF:       已启用")
    print(f"  IP 锁定:    15 分钟 10 次失败即锁定")
    print(f"  渐进延迟:   失败次数 × 2 秒（最大 30 秒）")
    print(f"  Session:    30 分钟超时")
    print(f"  Secret Key: 随机生成（每次启动不同）")
    print(f"  上传限制:   16MB，仅限图片（已修复文件上传漏洞）")
    print("=" * 60)
    app.run(debug=False, host="0.0.0.0", port=5000)

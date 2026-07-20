"""
简易用户信息管理平台
包含：登录、注册、搜索功能
"""
import sqlite3
import os

from flask import Flask, render_template, request, redirect, session, g

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# 数据库路径：data/users.db
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")


# ============================================================
# 数据库连接管理
# ============================================================

def get_db():
    """获取数据库连接（每个请求独立连接）"""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """请求结束后关闭数据库连接"""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库并插入默认用户"""
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email    TEXT,
            phone    TEXT
        )
    """)
    # 插入默认用户（明文密码）
    db.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
               ("admin", "admin123", "admin@example.com", "13800138000"))
    db.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
               ("alice", "alice2025", "alice@example.com", "13900139001"))
    db.commit()
    db.close()


# ============================================================
# 路由 — 首页
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            user_info = dict(row)
    return render_template("index.html", user=user_info, keyword="", results=None)


# ============================================================
# 路由 — 登录（保持原有功能不变）
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row and row["password"] == password:
            session["username"] = username
            user_info = dict(row)
            return render_template("index.html", user=user_info, keyword="", results=None)
        else:
            return render_template("login.html", error="用户名或密码错误！")

    msg = request.args.get("msg", "")
    return render_template("login.html", msg=msg)


# ============================================================
# 路由 — 注册（已修复：参数化查询替代 f-string 拼接）
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        db = get_db()
        # ✅ 已修复：使用参数化查询替代 f-string 拼接
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[REGISTER SQL] {sql} | params: ({username!r}, {password!r}, {email!r}, {phone!r})")
        try:
            db.execute(sql, (username, password, email, phone))
            db.commit()
            return redirect("/login?msg=注册成功，请登录")
        except Exception as e:
            return render_template("register.html", error=f"注册失败：{str(e)}")

    return render_template("register.html")


# ============================================================
# 路由 — 搜索（已修复：参数化查询替代 f-string 拼接）
# ============================================================

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        db = get_db()
        # ✅ 已修复：使用参数化查询替代 f-string 拼接，LIKE 通配符作为参数值
        pattern = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SEARCH SQL] {sql} | params: ('%{keyword}%', '%{keyword}%')")
        cur = db.execute(sql, (pattern, pattern))
        rows = cur.fetchall()
        results = [dict(row) for row in rows]

    # 获取当前登录用户信息
    username = session.get("username")
    user_info = None
    if username:
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            user_info = dict(row)

    return render_template("index.html", user=user_info, keyword=keyword, results=results)


# ============================================================
# 路由 — 退出
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
# 启动入口
# ============================================================

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  用户管理系统已启动")
    print("=" * 60)
    print(f"  监听地址: http://0.0.0.0:5000")
    print(f"  数据库:   {DATABASE}")
    print(f"  默认用户: admin/admin123, alice/alice2025")
    print(f"  SQL 注入: 已修复（参数化查询）")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)

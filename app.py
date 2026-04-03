from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "txt"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'General',
            upload_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    cursor.execute("PRAGMA table_info(users)")
    user_columns = [row["name"] for row in cursor.fetchall()]
    if "created_at" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        cursor.execute(
            "UPDATE users SET created_at = ? WHERE created_at IS NULL OR created_at = ''",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),)
        )

    cursor.execute("PRAGMA table_info(documents)")
    document_columns = [row["name"] for row in cursor.fetchall()]
    if "original_filename" not in document_columns:
        cursor.execute("ALTER TABLE documents ADD COLUMN original_filename TEXT")
        cursor.execute(
            "UPDATE documents SET original_filename = filename WHERE original_filename IS NULL OR original_filename = ''"
        )
    if "category" not in document_columns:
        cursor.execute("ALTER TABLE documents ADD COLUMN category TEXT NOT NULL DEFAULT 'General'")
    if "upload_date" not in document_columns:
        cursor.execute("ALTER TABLE documents ADD COLUMN upload_date TEXT")
        cursor.execute(
            "UPDATE documents SET upload_date = ? WHERE upload_date IS NULL OR upload_date = ''",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),)
        )

    conn.commit()

    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    admin_user = cursor.fetchone()

    if not admin_user:
        cursor.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (
                "admin",
                generate_password_hash("admin123"),
                "admin",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        )
        conn.commit()

    conn.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_logged_in():
    return "username" in session


def is_admin():
    return session.get("role") == "admin"


def format_datetime(value):
    if not value:
        return "N/A"
    try:
        dt = datetime.fromisoformat(value.replace("Z", ""))
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        try:
            dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%d %b %Y, %I:%M %p")
        except Exception:
            return value


app.jinja_env.filters["datetimeformat"] = format_datetime


@app.before_request
def setup_once():
    init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return redirect(url_for("register"))

        if len(password) < 4:
            flash("Password must be at least 4 characters long.", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                (
                    username,
                    hashed_password,
                    "member",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
            )
            conn.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists. Try another one.", "danger")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total_docs FROM documents")
    total_docs = cursor.fetchone()["total_docs"]

    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = cursor.fetchone()["total_users"]

    cursor.execute("SELECT COUNT(*) AS my_uploads FROM documents WHERE uploaded_by = ?", (session["username"],))
    my_uploads = cursor.fetchone()["my_uploads"]

    cursor.execute("""
        SELECT * FROM documents
        ORDER BY id DESC
        LIMIT 5
    """)
    recent_documents = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        total_docs=total_docs,
        total_users=total_users,
        my_uploads=my_uploads,
        recent_documents=recent_documents
    )


@app.route("/profile")
def profile():
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (session["username"],))
    user = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) AS uploaded_count FROM documents WHERE uploaded_by = ?", (session["username"],))
    uploaded_count = cursor.fetchone()["uploaded_count"]

    cursor.execute("""
        SELECT * FROM documents
        WHERE uploaded_by = ?
        ORDER BY id DESC
        LIMIT 5
    """, (session["username"],))
    recent_user_docs = cursor.fetchall()

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        uploaded_count=uploaded_count,
        recent_user_docs=recent_user_docs
    )


@app.route("/admin")
def admin_panel():
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can access the admin panel.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users ORDER BY id DESC")
    users = cursor.fetchall()

    cursor.execute("""
        SELECT * FROM documents
        ORDER BY id DESC
        LIMIT 10
    """)
    recent_documents = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = cursor.fetchone()["total_users"]

    cursor.execute("SELECT COUNT(*) AS total_docs FROM documents")
    total_docs = cursor.fetchone()["total_docs"]

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        recent_documents=recent_documents,
        total_users=total_users,
        total_docs=total_docs
    )


@app.route("/make-admin/<int:user_id>", methods=["POST"])
def make_admin(user_id):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can change user roles.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("User promoted to admin successfully.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/make-member/<int:user_id>", methods=["POST"])
def make_member(user_id):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can change user roles.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if user and user["username"] == "admin":
        conn.close()
        flash("Default admin cannot be changed to member.", "warning")
        return redirect(url_for("admin_panel"))

    cursor.execute("UPDATE users SET role = 'member' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("User changed to member successfully.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/reset-password/<int:user_id>", methods=["POST"])
def reset_password(user_id):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can reset user passwords.", "danger")
        return redirect(url_for("dashboard"))

    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not new_password or not confirm_password:
        flash("Both password fields are required.", "danger")
        return redirect(url_for("admin_panel"))

    if len(new_password) < 4:
        flash("New password must be at least 4 characters long.", "danger")
        return redirect(url_for("admin_panel"))

    if new_password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("admin_panel"))

    hashed_password = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
    conn.commit()
    conn.close()

    flash(f"Password reset successfully for {user['username']}.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can delete users.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("admin_panel"))

    if user["username"] == "admin":
        conn.close()
        flash("Default admin account cannot be deleted.", "warning")
        return redirect(url_for("admin_panel"))

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/files")
def files():
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM documents WHERE 1=1"
    params = []

    if search:
        query += " AND original_filename LIKE ?"
        params.append(f"%{search}%")

    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY id DESC"

    cursor.execute(query, params)
    documents = cursor.fetchall()

    cursor.execute("SELECT DISTINCT category FROM documents ORDER BY category ASC")
    categories = cursor.fetchall()

    conn.close()

    return render_template(
        "files.html",
        documents=documents,
        categories=categories,
        selected_category=category,
        search_value=search
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can upload files.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file was selected.", "danger")
            return redirect(url_for("upload"))

        file = request.files["file"]
        category = request.form.get("category", "General").strip()

        if not category:
            category = "General"

        if file.filename == "":
            flash("Please choose a file.", "danger")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("Invalid file type. Only PDF, DOC, DOCX, PPT, PPTX, and TXT are allowed.", "danger")
            return redirect(url_for("upload"))

        original_filename = secure_filename(file.filename)
        filename = original_filename

        name, ext = os.path.splitext(original_filename)
        counter = 1
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        while os.path.exists(save_path):
            filename = f"{name}_{counter}{ext}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            counter += 1

        file.save(save_path)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO documents (filename, original_filename, uploaded_by, category, upload_date)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                filename,
                original_filename,
                session["username"],
                category,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )
        conn.commit()
        conn.close()

        flash("File uploaded successfully.", "success")
        return redirect(url_for("files"))

    return render_template("upload.html")


@app.route("/viewer/<int:doc_id>")
def viewer(doc_id):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    document = cursor.fetchone()
    conn.close()

    if not document:
        flash("Document not found.", "danger")
        return redirect(url_for("files"))

    ext = document["filename"].rsplit(".", 1)[-1].lower()
    if ext != "pdf":
        flash("Viewer is available for PDF files only.", "warning")
        return redirect(url_for("files"))

    return render_template("viewer.html", document=document)


@app.route("/download/<path:filename>")
def download(filename):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    safe_filename = os.path.basename(filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)

    if not os.path.exists(file_path):
        flash("File not found.", "danger")
        return redirect(url_for("files"))

    return send_from_directory(app.config["UPLOAD_FOLDER"], safe_filename, as_attachment=True)


@app.route("/preview/<path:filename>")
def preview(filename):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    safe_filename = os.path.basename(filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)

    if not os.path.exists(file_path):
        flash("File not found.", "danger")
        return redirect(url_for("files"))

    ext = safe_filename.rsplit(".", 1)[-1].lower()
    if ext != "pdf":
        flash("Preview is available for PDF files only.", "warning")
        return redirect(url_for("files"))

    return send_from_directory(app.config["UPLOAD_FOLDER"], safe_filename)


@app.route("/delete/<int:doc_id>", methods=["POST"])
def delete_file(doc_id):
    if not is_logged_in():
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        flash("Only admin can delete files.", "danger")
        return redirect(url_for("files"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    document = cursor.fetchone()

    if not document:
        conn.close()
        flash("Document not found.", "danger")
        return redirect(url_for("files"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], document["filename"])

    if os.path.exists(file_path):
        os.remove(file_path)

    cursor.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

    flash("Document deleted successfully.", "success")
    return redirect(url_for("files"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.errorhandler(413)
def file_too_large(error):
    flash("File is too large. Maximum allowed size is 20MB.", "danger")
    return redirect(url_for("upload"))


@app.errorhandler(404)
def not_found(error):
    return "<h1>404 - Page Not Found</h1>", 404


if __name__ == "__main__":
    init_db()
    app.run()
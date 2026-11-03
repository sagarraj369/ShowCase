import os
import re
import secrets
from pathlib import Path
from contextlib import contextmanager
from functools import wraps

import psycopg
from psycopg.rows import dict_row
from psycopg.errors import UniqueViolation

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# CONFIGURATION
# ==========================================

DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is missing.")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is missing.")

UPLOAD_FOLDER = Path("/tmp/showcase_uploads")
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024


# ==========================================
# SUPPORTED LANGUAGES
# ==========================================

LANGUAGES = [
    "HTML", "Python", "CSS", "JavaScript",
    "Java", "TypeScript", "C", "C++", "C#", "PHP"
]


# ==========================================
# DATABASE CONNECTION
# ==========================================

@contextmanager
def get_db():
    with psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    ) as db:
        yield db


# ==========================================
# INITIALIZE DATABASE
# ==========================================

def initialize_database():

    with get_db() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                age INTEGER NOT NULL,
                education TEXT NOT NULL,
                college_job TEXT DEFAULT '',
                mobile TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                photo TEXT
            )
        """)

        db.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS college_job TEXT DEFAULT ''
        """)

        db.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS photo TEXT
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                language TEXT NOT NULL,
                code TEXT NOT NULL
            )
        """)


initialize_database()


# ==========================================
# CURRENT USER
# ==========================================

def get_current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    with get_db() as db:
        user = db.execute("""
            SELECT *, photo AS profile_picture
            FROM users
            WHERE id = %s
        """, (user_id,)).fetchone()

    return user


# ==========================================
# LOGIN REQUIRED
# ==========================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        user = get_current_user()

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# PHOTO UPLOAD
# ==========================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def save_photo(file):

    if not file or not file.filename:
        return None

    if not allowed_file(file.filename):
        raise ValueError(
            "Only PNG, JPG, JPEG and WEBP images are allowed."
        )

    extension = file.filename.rsplit(".", 1)[1].lower()
    filename = secrets.token_hex(16) + "." + extension

    file.save(UPLOAD_FOLDER / filename)

    return filename


def get_uploaded_photo():

    return (
        request.files.get("profile_picture")
        or request.files.get("photo")
    )


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("profile"))

    return redirect(url_for("register"))


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        age = request.form.get("age", "").strip()
        education = request.form.get("education", "").strip()
        college_job = request.form.get("college_job", "").strip()
        mobile = request.form.get("mobile", "").strip()

        if not name or not age or not education or not mobile:
            flash("Please fill all required fields.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(r"\d{10}", mobile):
            flash(
                "Mobile number must contain exactly 10 digits.",
                "error"
            )
            return redirect(url_for("register"))

        try:
            age_number = int(age)

            if age_number < 1 or age_number > 120:
                raise ValueError

        except ValueError:
            flash("Enter a valid age.", "error")
            return redirect(url_for("register"))

        try:

            photo = save_photo(get_uploaded_photo())

            password = str(secrets.randbelow(900000) + 100000)

            password_hash = generate_password_hash(password)

            with get_db() as db:

                new_user = db.execute("""
                    INSERT INTO users (
                        name, age, education,
                        college_job, mobile,
                        password_hash, photo
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    name,
                    age_number,
                    education,
                    college_job,
                    mobile,
                    password_hash,
                    photo
                )).fetchone()

                user_id = new_user["id"]

            session["new_pin"] = password
            session["new_user_id"] = user_id

            return redirect(url_for("show_password"))

        except UniqueViolation:

            flash(
                "This mobile number is already registered.",
                "error"
            )

        except ValueError as error:

            flash(str(error), "error")

    return render_template("register.html")


# ==========================================
# SHOW GENERATED PASSWORD
# ==========================================

@app.route("/password")
def show_password():

    password = session.pop("new_pin", None)
    user_id = session.pop("new_user_id", None)

    if not password or not user_id:
        return redirect(url_for("login"))

    return render_template(
        "password.html",
        password=password
    )


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "").strip()

        with get_db() as db:

            user = db.execute("""
                SELECT *
                FROM users
                WHERE mobile = %s
            """, (mobile,)).fetchone()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()
            session["user_id"] = user["id"]

            flash("Login successful.", "success")

            return redirect(url_for("profile"))

        flash(
            "Invalid mobile number or password.",
            "error"
        )

    return render_template("login.html")


# ==========================================
# PROFILE
# ==========================================

@app.route("/profile")
@login_required
def profile():

    user = get_current_user()

    search = request.args.get(
        "search",
        request.args.get("q", "")
    ).strip()

    with get_db() as db:

        if search:

            codes = db.execute("""
                SELECT *
                FROM codes
                WHERE user_id = %s
                AND title ILIKE %s
                ORDER BY id DESC
            """, (
                session["user_id"],
                "%" + search + "%"
            )).fetchall()

        else:

            codes = db.execute("""
                SELECT *
                FROM codes
                WHERE user_id = %s
                ORDER BY id DESC
            """, (
                session["user_id"],
            )).fetchall()

    return render_template(
        "profile.html",
        user=user,
        codes=codes,
        search=search
    )


# ==========================================
# UPDATE PROFILE
# ==========================================

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():

    name = request.form.get("name", "").strip()
    age = request.form.get("age", "").strip()
    education = request.form.get("education", "").strip()
    college_job = request.form.get("college_job", "").strip()

    if not name or not age or not education:
        flash("Please fill all required fields.", "error")
        return redirect(url_for("profile"))

    try:
        age_number = int(age)

        if age_number < 1 or age_number > 120:
            raise ValueError

    except ValueError:
        flash("Enter a valid age.", "error")
        return redirect(url_for("profile"))

    user = get_current_user()
    photo = user["photo"]

    try:

        uploaded_photo = save_photo(get_uploaded_photo())

        if uploaded_photo:
            photo = uploaded_photo

    except ValueError as error:

        flash(str(error), "error")
        return redirect(url_for("profile"))

    with get_db() as db:

        db.execute("""
            UPDATE users
            SET name = %s,
                age = %s,
                education = %s,
                college_job = %s,
                photo = %s
            WHERE id = %s
        """, (
            name,
            age_number,
            education,
            college_job,
            photo,
            session["user_id"]
        ))

    flash("Profile updated successfully.", "success")

    return redirect(url_for("profile"))


# ==========================================
# ADD CODE
# ==========================================

@app.route("/add_code", methods=["GET", "POST"])
@login_required
def add_code():

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        language = request.form.get("language", "").strip()
        code = request.form.get("code", "").strip()

        if not title or not language or not code:
            flash("Please fill all fields.", "error")
            return redirect(url_for("add_code"))

        if language not in LANGUAGES:
            flash("Select a supported language.", "error")
            return redirect(url_for("add_code"))

        if not title.endswith(".sr"):
            title += ".sr"

        with get_db() as db:

            db.execute("""
                INSERT INTO codes (
                    user_id, title, language, code
                )
                VALUES (%s, %s, %s, %s)
            """, (
                session["user_id"],
                title,
                language,
                code
            ))

        flash("Code added successfully.", "success")

        return redirect(url_for("profile"))

    return render_template(
        "add_code.html",
        languages=LANGUAGES
    )


# ==========================================
# EDIT CODE
# ==========================================

@app.route(
    "/edit_code/<int:code_id>",
    methods=["GET", "POST"]
)
@login_required
def edit_code(code_id):

    with get_db() as db:

        item = db.execute("""
            SELECT *
            FROM codes
            WHERE id = %s
            AND user_id = %s
        """, (
            code_id,
            session["user_id"]
        )).fetchone()

    if not item:
        flash("Code not found.", "error")
        return redirect(url_for("profile"))

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        language = request.form.get("language", "").strip()
        code = request.form.get("code", "").strip()

        if not title or not language or not code:
            flash("Please fill all fields.", "error")
            return redirect(
                url_for("edit_code", code_id=code_id)
            )

        if language not in LANGUAGES:
            flash("Select a supported language.", "error")
            return redirect(
                url_for("edit_code", code_id=code_id)
            )

        if not title.endswith(".sr"):
            title += ".sr"

        with get_db() as db:

            db.execute("""
                UPDATE codes
                SET title = %s,
                    language = %s,
                    code = %s
                WHERE id = %s
                AND user_id = %s
            """, (
                title,
                language,
                code,
                code_id,
                session["user_id"]
            ))

        flash(
            "Changes committed successfully.",
            "success"
        )

        return redirect(url_for("profile"))

    return render_template(
        "edit_code.html",
        code=item,
        item=item,
        languages=LANGUAGES
    )


# ==========================================
# VIEW CODE
# ==========================================

@app.route("/view_code/<int:code_id>")
@login_required
def view_code(code_id):

    with get_db() as db:

        item = db.execute("""
            SELECT *
            FROM codes
            WHERE id = %s
            AND user_id = %s
        """, (
            code_id,
            session["user_id"]
        )).fetchone()

    if not item:
        flash("Code not found.", "error")
        return redirect(url_for("profile"))

    return render_template(
        "view_code.html",
        code=item
    )


# ==========================================
# DELETE CODE
# ==========================================

@app.route(
    "/delete_code/<int:code_id>",
    methods=["GET", "POST"]
)
@login_required
def delete_code(code_id):

    with get_db() as db:

        result = db.execute("""
            DELETE FROM codes
            WHERE id = %s
            AND user_id = %s
        """, (
            code_id,
            session["user_id"]
        ))

    if result.rowcount:
        flash("Code deleted successfully.", "success")
    else:
        flash("Code not found.", "error")

    return redirect(url_for("profile"))


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    flash("Logged out successfully.", "success")

    return redirect(url_for("login"))


# ==========================================
# FILE SIZE ERROR
# ==========================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "Image is too large. Maximum size is 3 MB.",
        "error"
    )

    return redirect(url_for("profile"))


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )

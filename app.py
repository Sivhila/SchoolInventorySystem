import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, redirect, url_for, request, flash, session, g
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from helpers import init_db, admin_required
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("Inventory_Key")
app.config["ENV"] = "production"
app.config["DEBUG"] = False
app.config["SESSION_TYPE"] = os.getenv("SESSION_TYPE")


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(os.getenv("DATABASE"))
    return g.db

def get_cursor(db):
    return db.cursor(cursor_factory=psycopg2.extras.DictCursor)

def create_admin():
    db = get_db()
    cur = get_cursor(db)

    cur.execute("SELECT * FROM users WHERE username = %s", ("admin",))
    admin = cur.fetchone()

    if not admin:
        cur.execute("""
        INSERT INTO users (username, password_hash, role)
        VALUES (%s, %s, %s)
        """, ("admin", generate_password_hash("admin123"), "admin"))

        db.commit()

    cur.close()

def log_action(user_id, action, details=""):
    db = get_db()
    cur = get_cursor(db)
    cur.execute("""
    INSERT INTO activity_logs (user_id, action, details)
    VALUES (%s, %s, %s)
    """, (user_id, action, details))
    db.commit()
    cur.close

#Login Required Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("Must provide username")
            return redirect("/login")

        if not password:
            flash("Must provide password")
            return redirect("/login")

        db = get_db()
        cur = get_cursor(db)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password")
            return redirect("/login")

        session["user_id"] = user["id"]
        session["role"] = user["role"]

        log_action(user["id"], "LOGIN", "User logged in")

        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()
    flash("Logged out successfully")
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]
        role = request.form["role"]

        if password != confirm:
            flash("Passwords do not match")
            return redirect("/register")

        hashed = generate_password_hash(password)
        db = get_db()
        cur = get_cursor(db)

        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing = cur.fetchone()

        if existing:
            flash("Username already exists")
            cur.close()
            return redirect("/register")
        
        cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
        (username, hashed, role)
        )
        db.commit()
        cur.close()

        flash("Account created successfully")
        return redirect("/login")

    return render_template("register.html")



@app.route("/change_password", methods=["GET","POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form["current"]
        new = request.form["new"]

        db = get_db()
        cur = get_cursor(db)
        
        cur.execute("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
        user = cur.fetchone()

        if not check_password_hash(user["password_hash"], current):
            flash("Wrong current password")
            cur.close()
            return redirect("/change_password")

        cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (generate_password_hash(new), session["user_id"])
                )

        db.commit()
        cur.close()
        flash("Password updated successfully")

    return render_template("change_password.html")



@app.route("/")
@login_required
def dashboard():
    db = get_db()
    cur = get_cursor(db)

    cur.execute("SELECT COUNT(*) FROM items")
    total_items = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM items WHERE available_quantity <= 3")
    low_stock = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM issues WHERE status = 'issued'")
    active_issues = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM issues WHERE status = 'issued' AND due_date < CURRENT_TIMESTAMP")
    overdue = cur.fetchone()[0]

    cur.execute("""
    SELECT action, details, created_at
    FROM activity_logs
    ORDER BY created_at DESC
    LIMIT 5
    """)
    recent_logs = cur.fetchall()
    cur.close()

    return render_template(
            "dashboard.html",
            total_items=total_items,
            low_stock=low_stock,
            active_issues=active_issues,
            overdue=overdue,
            recent_logs=recent_logs
            )


@app.route("/items", methods=["GET", "POST"])
@login_required
def items():
    db = get_db()
    cur = get_cursor(db)

    if request.method == "POST":
        name = request.form["name"]
        category = request.form["category"]
        qty = int(request.form["quantity"])
        condition = request.form["condition"]

        cur.execute("""
        INSERT INTO items (name, category, total_quantity, available_quantity, item_condition
        VALUES (%s, %s, %s, %s, %s)
        """, (name, category, qty, qty, condition)
        )

        db.commit()

        log_action(session["user_id"], "ADD_ITEM", f"Added item '{name}' quantity {qty}")
        flash("Item added successfully")

    cur.execute("SELECT * FROM items")
    items = cur.fetchall()
    cur.close()

    return render_template("items.html", items=items)

@app.route("/issue", methods=["GET", "POST"])
@login_required
@admin_required
def issue_item():
    db = get_db()
    cur = get_cursor(db)

    if request.method == "POST":
        item_id = int(request.form["item_id"])
        user_id = int(request.form["user_id"])
        qty = int(request.form["quantity"])
        due_date = request.form["due_date"]

        cur.execute("SELECT available_quantity FROM items WHERE id = %s", (item_id,))
        items = cur.fetchone()

        if not item:
            flash("Item not found")
            return redirect("/issue")

        if qty <= 0:
            flash("Invalid quantity")
            return redirect("/issue")

        if item["available_quantity"] < qty:
            flash("Cannot issue more than available stock")
            return redirect("/issue")

        if not due_date:
            flash("Please select a due date")
            return redirect("/issue")

        cur.execute("""
        INSERT INTO issues (items_id, issued_to, issued_quantity, status, due_date)
        VALUES (%s, %s, %s, "issued", %s)
        """, (item_id, user_id, qty, due_date))

        cur.execute("""
        UPDATE items
        SET available_quantity = available_quantity - %s
        WHERE id = %s
        """, (qty, item_id))

        db.commit()
        log_action(session["user_id"], "ISSUE_ITEM", f"Issued {qty} of '{item['name']}' to user {user_id}")

        flash("Item issued successfully")

    cur.execute("SELECT * FROM items")
    items = cur.fetchall()
    
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    
    cur.close()

    return render_template("issue.html", items=items, users=users)


@app.route("/delete_item/<int:item_id>")
@login_required
def delete_item(item_id):
    db = get_db()
    cur = get_cursor(db)

    cur.execute("""
    SELECT COUNT(*) AS total
    FROM issues
    WHERE item_id = %s AND status = "issued"
    """, (item_id,))
    active = cur.fetchone()

    if active["total"] > 0:
        flash("Cannot delete item - it has issues")
        return redirect("/items")

    cur.execute("SELECT name FROM items WHERE id = %s", (item_id,))
    item = cur.fetchone()

    cur.execute("DELETE FROM items WHERE id = %s", (item_id,))
    db.commit()

    log_action(session["user_id"], "DELETE_ITEM", f"Deleted item '{item['name']}'")
    
    flash("Item deleted successfully")
    return redirect("/items")


@app.route("/logs")
@login_required
def logs():
    db = get_db()
    cur = get_cursor(db)

    cur.execute("""
    SELECT activity_logs.*, users.username
    FROM activity_logs
    LEFT JOIN users ON users.id = activity_logs.user_id
    ORDER BY created_at DESC
    """)
    logs = cur.fetchall()
    cur.close()
    
    return render_template("logs.html", logs=logs)


@app.route("/return/<int:issue_id>")
@login_required
@admin_required
def return_item(issue_id):
    db = get_db()
    cur = get_cursor(db)

    cur.execute("""
    SELECT issues.*, items.name
    FROM issues
    JOIN items ON items.id = issues.item_id
    WHERE issues.id = %s AND issues.status = "issued"
    """, (issue_id,))
    issue = cur.fetchone()

    if not issue:
        flash("Issue not found or already returned")
        cur.close()
        return redirect("/")

    cur.execute("""
    UPDATE items
    SET available_quantity = available_quantity + %s
    WHERE id = %s
    """, (issue['issued_quantity'], issue['item_id']))

    cur.execute("""
    UPDATE issues
    SET status = 'returned',
    return_date = CURRENT_TIMESTAMP
    WHERE id = %s
    """, (issue_id,))

    db.commit()
    cur.close()

    log_action(session["user_id"], "RETURN_ITEM", f"Returned {issue['issued_quantity']} of '{issue['name']}'")
    flash("Item returned successfully")
    return redirect("/")


@app.route("/active_issues")
@login_required
def active_issues():
    db = get_db()
    cur = get_cursor(db)

    cur.execute("""
    SELECT issues.*, items.name, users.username
    FROM issues
    JOIN items ON items.id = issues.item_id
    JOIN users ON users.id = issues.issued_to
    WHERE issues.status = 'issued'
    ORDER BY issue_date DESC
    """)
    issues = cur.fetchall()
    cur.close()

    return render_template("active_issues.html", issues=issues)


@app.route("/overdue")
@login_required
def overdue_items():
    db = get_db()
    cur = get_cursor(db)

    cur.execute("""
    SELECT issues.*, items.name, users.username
    FROM issues
    JOIN items ON items.id = issues.item_id
    JOIN users ON users.id = issues.issued_to
    WHERE issues.status = 'issued'
    AND issues.due_date < CURRENT_TIMESTAMP
    ORDER BY issues.due_date ASC
    """)
    overdue = cur.fetchall()
    cur.close

    return render_template("overdue.html", overdue=overdue)


with app.app_context():
    init_db()
    create_admin()

if __name__ == "__main__":
    app.run()


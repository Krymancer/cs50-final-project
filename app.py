import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import math

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Begin Model-View-Controller Logic
# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///tuiter.db")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    tweets = db.execute("SELECT tweets.id, content, users.username as author, likes FROM tweets JOIN users ON users.id = tweets.author ORDER BY tweets.id DESC")

    print("twwets",tweets)

    return render_template("index.html", tweets=tweets)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password1 = request.form.get("password")
        password2 = request.form.get("confirmation")
        

        special_symbols = ['!', '#', '$', '%', '.', '_', '&']

        if not username:
            return apology("You must provide a username.", 400)

        if not password1:
            return apology("You must provide a password.", 400)

        if not password2:
            return apology("You must confirm your password.", 400)

        if len(password1) < 8:
            return apology("Your password must contain 8 or more characters.", 400)

        if not any(char.isdigit() for char in password1):
            return apology("Your password must contain at least 1 number.", 400)

        if not any(char.isupper() for char in password1):
            return apology("Your password must contain at least uppercase letter.", 400)

        if not any(char in special_symbols for char in password1):
            return apology("Your password must contain at least 1 approved symbol.", 400)

        if password1 == password2:
            password = password1
        else:
            return apology("Passwords do not match.", 400)

        p_hash = generate_password_hash(password, method = 'pbkdf2:sha256', salt_length = 8)

        if len(db.execute("SELECT username FROM users WHERE username == :username", username=username)) == 0:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=p_hash)
            return redirect("/")
        else:
            return apology("Username already exists. Please enter a new username.", 400)
    else:
        return render_template("register.html")

@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    """Post a tweet"""
    if request.method == "POST":
        content = request.form.get("content")
        author = session["user_id"]

        if not content:
            return apology("You must provide a tweet.", 400)

        db.execute("INSERT INTO tweets (content, author, likes) VALUES (:content, :author, 0)", content=content, author=author)
        return redirect("/")
    else:
        return render_template("post.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
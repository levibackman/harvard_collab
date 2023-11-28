import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(
        "SELECT symbol, quantity, SUM(quantity) as total_shares FROM purchases WHERE user_id = ? GROUP BY symbol  HAVING total_shares > 0",
        session["user_id"],
    )
    total_stock_value = 0
    total_holdings_value = 0
    for stock in stocks:
        quote = lookup(stock["symbol"])
        if quote:
            stock["current_price"] = quote["price"]
            stock["current_holding_value"] = quote["price"] * stock["total_shares"]
            total_stock_value = total_stock_value + stock["current_holding_value"]

    rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = rows[0]["cash"]
    total_holdings_value = total_stock_value + cash
    return render_template(
        "/index.html",
        stocks=stocks,
        cash=cash,
        total_holdings_value=total_holdings_value,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure stock symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        # Ensure valid stock symbol was submitted
        stock = lookup(request.form.get("symbol"))
        print(stock)
        if not stock:
            return apology("must provide valid stock symbol", 400)

        # Ensure a quantity of shares was submitted
        if not request.form.get("shares"):
            return apology("must provide desired quatity of stock", 400)

        # Ensure valid quantity of shares was submitted
        shares = request.form.get("shares")
        if not shares.isdigit() or int(shares) <= 0:
            return apology("must provide positive integer value of shares", 400)

        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]
        cost = stock["price"] * int(shares)
        if cost > cash:
            return apology(
                "you don't have enough cash to complete this transaction", 400
            )
        else:
            db.execute(
                "UPDATE users SET cash = cash - ? WHERE id = ?",
                cost,
                session["user_id"],
            )
            db.execute(
                "INSERT INTO purchases (user_id, symbol, quantity, price) VALUES (?, ?, ?, ?)",
                session["user_id"],
                stock["symbol"],
                int(shares),
                stock["price"],
            )

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("/buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    purchases = db.execute(
        "SELECT symbol, quantity, price, transacted FROM purchases WHERE user_id = ? ORDER BY transacted DESC",
        session["user_id"],
    )
    return render_template("/history.html", purchases=purchases)


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
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure stock symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        # Ensure valid stock symbol was submitted
        quote = lookup(request.form.get("symbol"))
        print(quote)
        if not quote:
            return apology("must provide valid stock symbol", 400)
        return render_template("quoted.html", quote=quote)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must create username", 400)

        # Enure username is not taken
        if (
            len(
                db.execute(
                    "SELECT username FROM users WHERE username = ?",
                    request.form.get("username"),
                )
            )
            > 0
        ):
            return apology(
                "please choose different username, inputted username taken", 400
            )

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must create password", 400)

        # Ensure confirmation password was submitted
        if not request.form.get("confirmation"):
            return apology("must confirm created password", 400)

        # Ensure thst password and confirmation password match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        username = request.form.get("username")
        hashedpassword = generate_password_hash(request.form.get("password"))

        # Insert data into database and Remember which user has logged in
        new_user_id = db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)", username, hashedpassword
        )
        session["user_id"] = new_user_id

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure stock symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        # Ensure valid stock symbol was submitted
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("must provide valid stock symbol", 400)

        # Ensure a quantity of shares was submitted
        if not request.form.get("shares"):
            return apology("must provide desired quantity of stock", 400)

        # Ensure valid quantity of shares was submitted
        shares = request.form.get("shares")
        if not shares.isdigit() or int(shares) <= 0:
            return apology("must provide positive integer value of shares", 400)

        rows = db.execute(
            "SELECT quantity, SUM (quantity) as total_shares FROM purchases WHERE user_id = ? AND symbol = ? GROUP BY SYMBOL",
            session["user_id"],
            stock["symbol"],
        )
        if not rows:
            return apology("You don't own any shares of this stock", 400)
        total_shares = rows[0]["total_shares"]
        cost = stock["price"] * int(shares)
        if total_shares < int(shares):
            return apology("you don't own enough shares", 400)
        else:
            db.execute(
                "UPDATE users SET cash = cash + ? WHERE id = ?",
                cost,
                session["user_id"],
            )
            db.execute(
                "INSERT INTO purchases (user_id, symbol, quantity, price) VALUES (?, ?, ?, ?)",
                session["user_id"],
                stock["symbol"],
                -int(shares),
                stock["price"],
            )

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        rows = db.execute(
            "SELECT DISTINCT symbol FROM purchases WHERE user_id = ? ORDER BY symbol",
            session["user_id"],
        )
        symbols = [row["symbol"] for row in rows]
        return render_template("/sell.html", symbols=symbols)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must input username", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("old password is incorrect", 400)

        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return apology("must create new password", 400)

        # Ensure confirmation of new password was submitted
        if not request.form.get("confirm_new_password"):
            return apology("must rewrite new created password", 400)

        # Ensure that new password and confirmation password match
        if request.form.get("new_password") != request.form.get("confirm_new_password"):
            return apology("new passwords must match", 400)

        hash_new_password = generate_password_hash(request.form.get("new_password"))
        db.execute(
            "UPDATE users SET hash = ? WHERE username = ?",
            hash_new_password,
            request.form.get("username"),
        )

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_password.html")

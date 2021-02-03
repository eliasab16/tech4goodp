from flask import Flask, redirect, url_for, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, passwordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

app = Flask(__name__)
# key for encryption
app.secret_key = "tech4good"


class LoginForm(FlaskForm):
    username = StringField(
        "username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = passwordField(
        "password", validators=[InputRequired(), Length(min=8, max=80)]
    )


# stay logged in with most recent user for 5 minutes
app.permanent_session_lifetime = timedelta(minutes=5)

# setup database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"

db = SQLAlchemy(app)


# class users(db.Model):
#     __tablename__ = "flasklogin-users"
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False, unique=True)
#     email = db.Column(db.String(100), nullable=False, unique=True)
#     pasword = db.Column(db.String(100), nullable=False, unique=False)

#     # create hashed password
#     def set_password(self, password):
#         self.password = generate_password_hash(password, method="sha256")

#     # check hashed password
#     def check_password(self, password):
#         return check_password_hash(self.password, password)

#     def __repr__(self):
#         return "<User {}>".format(self.username)

#     def __init__(self, name, email):
#         self.name = name
#         self.email = email


class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), unique=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


# path to function home
@app.route("/")
# define function
def home():
    return render_template("index.html", content="how can I help you?")


@app.route("/login", methods=["POST", "GET"])
# define function
def login():
    form = LoginForm()
    if "user" in session:
        user = session["user"]
        return redirect(url_for("user"))
    # receive the name passed to the input field
    elif request.method == "POST":
        session.permanent = True
        user = request.form["nm"]
        email = request.form["email"]
        password = request.form["pwd"]

        user_exists = users.query.filter_by(email=email).first()
        # if user is new
        if not user_exists:
            new = users(name=user, email=email, password=password)
            db.session.add(new)
            db.session.commit()
            session["user"] = user

            return redirect(url_for("user"))
        # if user exists
        else:
            if user_exists and user_exists.password == password:
                session["user"] = user
            else:
                flash("invalid user credentials")
                return redirect(url_for("login"))
    else:
        return render_template("login.html")


@app.route("/user", methods=["POST", "GET"])
def user():
    email = None
    # check if there is a login
    if "user" in session:
        user = session["user"]

        # if user submitted email address
        if request.method == "POST":
            email = request.form["email"]
            session["email"] = email
        else:
            # if email already exists, look it up from the session
            if "email" in session:
                email = session["email"]

        return render_template("user.html", email=email)
    else:
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("email", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
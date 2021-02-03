from flask import Flask, redirect, url_for, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import UserMixin
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

app = Flask(__name__)
Bootstrap(app)
# key for encryption
app.secret_key = "tech4good"
# setup database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    username = StringField(
        "username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = PasswordField(
        "password", validators=[InputRequired(), Length(min=8, max=80)]
    )


class RegisterForm(FlaskForm):
    username = StringField(
        "username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = PasswordField(
        "password", validators=[InputRequired(), Length(min=8, max=80)]
    )
    email = StringField("email", validators=[InputRequired(), Length(max=50)])


# stay logged in with most recent user for 5 minutes
app.permanent_session_lifetime = timedelta(minutes=5)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), unique=False)


# path to function home
@app.route("/")
# define function
def home():
    return render_template("index.html", content="how can I help you?")


@app.route("/login", methods=["POST", "GET"])
# define function
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                return redirect(url_for("home"))

    return render_template("login.html", form=form)


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


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        return "<h1>New user has been created </h1>"

    return render_template("register.html", form=form)


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("email", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
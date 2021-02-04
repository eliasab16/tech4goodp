from flask import (
    Flask,
    redirect,
    url_for,
    flash,
    render_template,
    request,
    session,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import UserMixin
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

app = Flask(__name__)
Bootstrap(app)
# key for encryption
app.secret_key = "tech4good"
# setup database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


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


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), unique=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
                login_user(user)
                return redirect(url_for("profile"))
        else:
            flash("Invalid user credentials!")
    return render_template("login.html", form=form)


# cannot access profile unless authorized
@app.route("/profile", methods=["POST", "GET"])
@login_required
def profile():
    return render_template(
        "profile.html", name=current_user.username, email=current_user.email
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash("Username already exists!")

            return redirect(url_for("register"))

        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        flash("New user registered.")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
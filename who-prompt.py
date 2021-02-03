from flask import Flask, redirect, url_for, render_template, request, session

app = Flask(__name__)
# key for encryption
app.secret_key = "tech4good"

# path to function home
@app.route("/")
# define function
def home():
    return render_template("index.html", content="how can I help you?")


@app.route("/login", methods=["POST", "GET"])
# define function
def login():
    if "user" in session:
        user = session["user"]
        return redirect(url_for("user"))
    # receive the name passed to the input field
    elif request.method == "POST":
        user = request.form["nm"]
        session["user"] = user
        return redirect(url_for("user"))
    else:
        return render_template("login.html")


@app.route("/user")
def user():
    # check if there is a login
    if "user" in session:
        user = session["user"]
        return render_template("user.html")
    else:
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
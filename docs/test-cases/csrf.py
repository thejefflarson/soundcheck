# Test case: csrf (A01:2025)
from flask import Flask, request, redirect, make_response

app = Flask(__name__)
app.secret_key = "supersecret"


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if request.method == "POST":
        amount = request.form["amount"]
        to_account = request.form["to"]
        # BUG: no CSRF token validation on state-changing endpoint
        execute_transfer(amount, to_account)
        return redirect("/done")
    # BUG: form rendered without CSRF token hidden field
    return """
    <form method="POST" action="/transfer">
        <input name="amount" />
        <input name="to" />
        <button type="submit">Send</button>
    </form>
    """


@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["user"], request.form["pass"])
    resp = make_response(redirect("/dashboard"))
    # BUG: session cookie missing SameSite attribute
    resp.set_cookie("session", user.session_id, httponly=True)
    return resp


def execute_transfer(amount, to_account):
    pass


def authenticate(user, password):
    pass

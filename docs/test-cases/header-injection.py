"""HTTP header injection — intentionally vulnerable. DO NOT deploy."""
from flask import Flask, request, make_response

app = Flask(__name__)

# BUG: user input directly in response header — CRLF injection
@app.route("/download")
def download():
    filename = request.args.get("name", "file.txt")
    resp = make_response("file content here")
    # Attacker: name=file.txt%0d%0aX-Injected:%20true
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp

# BUG: reflecting request header into response without sanitization
@app.route("/api")
def api():
    request_id = request.headers.get("X-Request-Id", "none")
    resp = make_response({"ok": True})
    # Attacker sends X-Request-Id: foo\r\nSet-Cookie: session=hijacked
    resp.headers["X-Request-Id"] = request_id
    return resp

# BUG: user input in Location header
@app.route("/redirect")
def redirect_endpoint():
    url = request.args.get("url")
    resp = make_response("", 302)
    resp.headers["Location"] = url  # CRLF splits response
    return resp

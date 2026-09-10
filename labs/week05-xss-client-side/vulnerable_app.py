"""Deliberately INSECURE — Week 5 Cross-Site Scripting (XSS). Sandbox only; for authorized lab use."""
from flask import Flask, request, Response
from markupsafe import escape

app = Flask(__name__)

# In-memory comment board (resets on restart).
COMMENTS = []

# Example payloads to try in the browser:
#   Reflected:  /hello?name=<script>alert(1)</script>
#   Reflected:  /hello?name=<img src=x onerror=alert(1)>
#   Stored:     POST a comment with body  <script>alert(document.cookie)</script>


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # CWE-79: reflected XSS — user input echoed into HTML without escaping.
    # html = "<h1>Hello, " + name + "!</h1>"    ---- Final Fix
    html = "<h1>Hello, " + str(escape(name)) + "!</h1>"
    return Response(html, mimetype="text/html")


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        # CWE-79: stored XSS — raw comment body persisted, later rendered unescaped.
        COMMENTS.append(request.form.get("body", ""))
    body = "<form method=post><input name=body><input type=submit value=Post></form><hr>"
    # Each stored comment is concatenated into the page as raw HTML.
    body += "".join("<div class=comment>" + c + "</div>" for c in COMMENTS)
    return Response("<h2>Comments</h2>" + body, mimetype="text/html")


@app.route("/")
def index():
    # No security headers at all: no Content-Security-Policy, cookies set without HttpOnly/SameSite.
    resp = Response("<a href=/hello?name=you>hello</a> | <a href=/comments>comments</a>",
                    mimetype="text/html")
    # CWE-1004 / CWE-79 amplifier: cookie readable by JS (no HttpOnly) and sent cross-site (no SameSite).
    resp.set_cookie("session", "abc123")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

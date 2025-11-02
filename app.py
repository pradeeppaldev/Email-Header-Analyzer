# app.py
from flask import Flask, render_template, request
from parser import parse_headers, parse_received, get_first
from analyzer import find_auth_results, alignment_hint, risk_flags

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw = request.form.get("headers", "")
        headers = parse_headers(raw)
        received = parse_received(headers)
        auth = find_auth_results(headers)
        align = alignment_hint(headers)
        flags = risk_flags(headers, received, auth)

        key_fields = {
            "From": get_first(headers, "From"),
            "To": get_first(headers, "To"),
            "Subject": get_first(headers, "Subject"),
            "Date": get_first(headers, "Date"),
            "Message-ID": get_first(headers, "Message-ID"),
            "Return-Path": get_first(headers, "Return-Path"),
            "Reply-To": get_first(headers, "Reply-To"),
            "MIME-Version": get_first(headers, "MIME-Version"),
            "Content-Type": get_first(headers, "Content-Type"),
        }

        return render_template(
            "result.html",
            key_fields=key_fields,
            auth=auth,
            align=align,
            received=received,
            flags=flags,
            raw=raw
        )
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

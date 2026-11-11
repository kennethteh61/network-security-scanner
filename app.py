from flask import Flask, render_template, request
from scanner import scan_target

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan")
def scan():
    target = request.args.get("target")
    scan_data = scan_target(target)

    if scan_data["risk_level"] == "INVALID":
        return render_template(
            "results.html",
            results=[],
            open_ports=0,
            risk_level="INVALID",
            error="Please enter a valid IP address."
        )

    return render_template(
        "results.html",
        results=scan_data["results"],
        open_ports=scan_data["open_ports"],
        risk_level=scan_data["risk_level"],
        error=""
    )


if __name__ == "__main__":
    app.run(debug=True)
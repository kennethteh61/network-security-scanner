
from flask import Flask, render_template, request, jsonify
from scanner import scan_target
from database import (
    create_database,
    save_scan,
    get_scan_history,
    get_dashboard_stats
)

app = Flask(__name__)

# Create the database table when the application starts
create_database()


@app.route("/")
def home():
    stats = get_dashboard_stats()

    return render_template(
        "index.html",
        stats=stats
    )


@app.route("/scan")
def scan():
    target = request.args.get("target", "").strip()

    scan_data = scan_target(target)

    if scan_data["risk_level"] == "INVALID":
        return render_template(
            "results.html",
            results=[],
            open_ports=0,
            risk_level="INVALID",
            error="Please enter a valid IP address.",
            target=target
        )

    # Automatically save valid scan results
    save_scan(target, scan_data)

    return render_template(
        "results.html",
        results=scan_data["results"],
        open_ports=scan_data["open_ports"],
        risk_level=scan_data["risk_level"],
        error="",
        target=target
    )


@app.route("/api/scan", methods=["GET"])
def api_scan():
    target = request.args.get("target", "").strip()

    scan_data = scan_target(target)

    if scan_data["risk_level"] == "INVALID":
        return jsonify({
            "success": False,
            "error": "Please enter a valid IP address."
        }), 400

    # Save completed scan
    save_scan(target, scan_data)

    return jsonify({
        "success": True,
        "target": target,
        "results": scan_data["results"],
        "open_ports": scan_data["open_ports"],
        "risk_level": scan_data["risk_level"]
    })

@app.route("/history")
def history():
    scan_history = get_scan_history()

    return render_template(
        "history.html",
        history=scan_history
    )


if __name__ == "__main__":
    app.run(debug=True)

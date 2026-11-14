from flask import Flask, render_template, request, make_response
import csv
import io
from scanner import scan_target
from database import (
    create_database,
    save_scan,
    get_scan_history,
    get_dashboard_stats,
    get_scan_by_id
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


@app.route("/history/<int:scan_id>")
def scan_details(scan_id): 
    scan = get_scan_by_id(scan_id)

    if scan is None:
        return "Scan record not found.", 404

    return render_template(
        "scan_details.html",
        scan=scan
    )
@app.route("/history/<int:scan_id>/export")
def export_scan_csv(scan_id):
    scan = get_scan_by_id(scan_id)

    if scan is None:
        return "Scan record not found.", 404

    output = io.StringIO()
    writer = csv.writer(output)

    # CSV report heading
    writer.writerow(["Network Security Scan Report"])
    writer.writerow(["Scan ID", scan["id"]])
    writer.writerow(["Target IP", scan["target_ip"]])
    writer.writerow(["Scan Date", scan["scan_date"]])
    writer.writerow(["Risk Level", scan["risk_level"]])
    writer.writerow(["Total Open Ports", scan["open_ports"]])
    writer.writerow([])

    # Port details
    writer.writerow([
        "Port",
        "Service",
        "Version",
        "Status",
        "Security Warning"
    ])

    for result in scan["results"]:
        writer.writerow([
            result.get("port", "Unknown"),
            result.get("service", "Unknown"),
            result.get("version", "Unknown"),
            result.get("status", "Unknown"),
            result.get("warning", "None")
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = (
        f"attachment; filename=scan_report_{scan_id}.csv"
    )
    response.headers["Content-Type"] = "text/csv; charset=utf-8"

    return response

if __name__ == "__main__":
    app.run(debug=True)

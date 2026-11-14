
import sqlite3
import json
from datetime import datetime


DATABASE_NAME = "scan_history.db"


def create_database():
    """Create the scan history table if it does not exist."""

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            open_ports INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            results TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(target_ip, scan_data):
    """Save a completed scan into the database."""

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = json.dumps(scan_data["results"])

    cursor.execute("""
        INSERT INTO scan_history
        (target_ip, scan_date, open_ports, risk_level, results)
        VALUES (?, ?, ?, ?, ?)
    """, (
        target_ip,
        scan_date,
        scan_data["open_ports"],
        scan_data["risk_level"],
        results
    ))

    connection.commit()
    connection.close()


def get_scan_history():
    """Retrieve all previous scans from the database."""

    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM scan_history
        ORDER BY id DESC
    """)

    history = cursor.fetchall()
    connection.close()

    return history


def get_dashboard_stats():
    """Retrieve statistics for the main dashboard."""

    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Total number of scans
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    # Total number of open ports detected
    cursor.execute("SELECT SUM(open_ports) FROM scan_history")
    total_open_ports = cursor.fetchone()[0] or 0

    # Number of high-risk scans
    cursor.execute("""
        SELECT COUNT(*) FROM scan_history
        WHERE risk_level = 'HIGH'
    """)
    high_risk_scans = cursor.fetchone()[0]

    # Number of unique IP addresses scanned
    cursor.execute("""
        SELECT COUNT(DISTINCT target_ip)
        FROM scan_history
    """)
    unique_targets = cursor.fetchone()[0]

    # Count scans by risk level
    cursor.execute("""
        SELECT risk_level, COUNT(*)
        FROM scan_history
        GROUP BY risk_level
    """)

    risk_data = cursor.fetchall()

    risk_distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }

    for risk, count in risk_data:
        if risk in risk_distribution:
            risk_distribution[risk] = count

    # Retrieve the five most recent scans
    cursor.execute("""
        SELECT * FROM scan_history
        ORDER BY id DESC
        LIMIT 5
    """)
    recent_scans = cursor.fetchall()

    connection.close()

    return {
        "total_scans": total_scans,
        "total_open_ports": total_open_ports,
        "high_risk_scans": high_risk_scans,
        "unique_targets": unique_targets,
        "recent_scans": recent_scans,
        "risk_distribution": risk_distribution
    }

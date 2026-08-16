```python
from flask import Flask, jsonify, request

from utils import resolve_target, parse_port_range, format_duration
from logger import setup_logger
from hostinfo import get_hostname, is_host_alive, get_service_name
import risk
import database

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# --------------------------------------------------
# Flask Application
# --------------------------------------------------

app = Flask(__name__)

logger = setup_logger()


# --------------------------------------------------
# Port Scanner
# --------------------------------------------------

def scan_port(ip, port, timeout=1.0):
    """Attempt a TCP connection to a single port."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))

            return result == 0

    except socket.error:
        return False


# --------------------------------------------------
# Scan Workflow
# --------------------------------------------------

def run_scan(
    target,
    port_str="1-1024",
    threads=100,
    timeout=1.0,
    check_alive=True
):
    """
    Full scan workflow:

    1. Resolve target hostname/IP
    2. Optionally check whether host is alive
    3. Scan ports concurrently
    4. Assess risk of open ports
    5. Save results to database
    6. Log progress

    Returns a summary dictionary.
    """

    database.init_db()

    # Resolve target
    ip = resolve_target(target)

    hostname = get_hostname(ip) or target

    # Parse ports
    ports = parse_port_range(port_str)

    logger.info(
        f"Starting scan on {target} ({ip}) — "
        f"{len(ports)} ports, {threads} threads"
    )

    # Optional host check
    if check_alive and not is_host_alive(ip):

        logger.warning(
            f"Host {ip} did not respond to ping — "
            f"continuing anyway (ICMP may be blocked)"
        )

    # Create scan record
    scan_id = database.create_scan(
        target,
        ip,
        hostname,
        port_str
    )

    open_ports = []

    start = time.time()

    # Concurrent port scanning
    with ThreadPoolExecutor(max_workers=threads) as executor:

        future_to_port = {
            executor.submit(
                scan_port,
                ip,
                port,
                timeout
            ): port

            for port in ports
        }

        for future in as_completed(future_to_port):

            port = future_to_port[future]

            try:
                is_open = future.result()

            except Exception as e:

                logger.error(
                    f"Error scanning port {port}: {e}"
                )

                continue

            if is_open:

                service, risk_level, note = risk.assess_port(port)

                sys_service = get_service_name(port)

                open_ports.append(port)

                database.add_result(
                    scan_id,
                    port,
                    "open",
                    service if service != "unknown" else sys_service,
                    risk_level,
                    note
                )

                logger.info(
                    f"Port {port} OPEN — "
                    f"{service} [{risk_level}]"
                )

    # Finish scan
    elapsed = time.time() - start

    open_ports.sort()

    database.finish_scan(
        scan_id,
        len(open_ports)
    )

    # Risk summary
    summary = risk.summarize_risk(open_ports)

    summary.update({
        "scan_id": scan_id,
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "duration": format_duration(elapsed),
        "ports_scanned": len(ports),
    })

    logger.info(
        f"Scan complete: "
        f"{len(open_ports)}/{len(ports)} ports open "
        f"in {summary['duration']} "
        f"(highest risk: {summary['highest_risk']})"
    )

    return summary


# --------------------------------------------------
# Home Route
# --------------------------------------------------

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "online",
        "message": "Port Scanner API is running",
        "usage": "POST /scan to start a scan"
    })


# --------------------------------------------------
# Scan API
# --------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json(silent=True) or {}

        target = data.get("target")

        port_str = data.get(
            "ports",
            "1-1024"
        )

        threads = int(
            data.get(
                "threads",
                100
            )
        )

        timeout = float(
            data.get(
                "timeout",
                1.0
            )
        )

        check_alive = data.get(
            "check_alive",
            True
        )

        # Validate target
        if not target:

            return jsonify({
                "success": False,
                "error": "Target is required"
            }), 400

        # Basic validation
        if threads < 1:

            return jsonify({
                "success": False,
                "error": "Threads must be at least 1"
            }), 400

        if timeout <= 0:

            return jsonify({
                "success": False,
                "error": "Timeout must be greater than 0"
            }), 400

        logger.info(
            f"API scan request received for {target}"
        )

        # Run scanner
        result = run_scan(
            target=target,
            port_str=port_str,
            threads=threads,
            timeout=timeout,
            check_alive=check_alive
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as e:

        logger.exception(
            "Scan API error"
        )

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# --------------------------------------------------
# Health Check
# --------------------------------------------------

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "healthy"
    })


# --------------------------------------------------
# Manual Terminal Test
# --------------------------------------------------

if __name__ == "__main__":

    # Local development server
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
```

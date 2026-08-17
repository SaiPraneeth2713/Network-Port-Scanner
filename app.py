import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request

from utils import resolve_target, parse_port_range, format_duration
from logger import setup_logger
from hostinfo import get_hostname, is_host_alive, get_service_name
import risk
import database


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

logger = setup_logger()


# =========================================================
# WEB ACTIVITY LOG HELPER
# =========================================================

def add_scan_log(activity_log, message, level="INFO"):
    """
    Add a message to the web UI activity log.

    The message is stored in the list and later displayed
    inside index.html.
    """

    if activity_log is None:
        return

    activity_log.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message
    })


# =========================================================
# PORT SCANNER
# =========================================================

def scan_port(ip, port, timeout=1.0):
    """
    Attempt a TCP connection to a single port.

    Returns:
        True  -> port is open
        False -> port is closed/unavailable
    """

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex(
                (ip, port)
            )

            return result == 0

    except socket.error:

        return False


# =========================================================
# MAIN SCAN FUNCTION
# =========================================================

def run_scan(
    target,
    port_str="1-1024",
    threads=100,
    timeout=1.0,
    check_alive=True,
    activity_log=None
):
    """
    Full network port scanning workflow.

    Steps:
        1. Resolve target hostname/IP
        2. Optionally check whether host is alive
        3. Parse port range
        4. Scan ports concurrently
        5. Assess risk of open ports
        6. Store results in SQLite
        7. Send activity messages to the UI
        8. Return scan summary
    """

    # =====================================================
    # INITIALIZE DATABASE
    # =====================================================

    database.init_db()

    # =====================================================
    # RESOLVE TARGET
    # =====================================================

    try:

        ip = resolve_target(target)

    except Exception as e:

        logger.error(
            f"Unable to resolve target {target}: {e}"
        )

        add_scan_log(
            activity_log,
            f"Unable to resolve target {target}: {e}",
            "ERROR"
        )

        raise ValueError(
            f"Unable to resolve target: {target}"
        )

    hostname = get_hostname(ip) or target

    # =====================================================
    # PARSE PORT RANGE
    # =====================================================

    try:

        ports = parse_port_range(port_str)

    except Exception as e:

        add_scan_log(
            activity_log,
            f"Invalid port range: {e}",
            "ERROR"
        )

        raise ValueError(
            f"Invalid port range: {port_str}"
        )

    if not ports:

        add_scan_log(
            activity_log,
            "No valid ports were provided.",
            "ERROR"
        )

        raise ValueError(
            "No valid ports were provided."
        )

    # =====================================================
    # START MESSAGE
    # =====================================================

    start_message = (
        f"Starting scan on {target} ({ip}) — "
        f"{len(ports)} ports, {threads} threads"
    )

    logger.info(start_message)

    add_scan_log(
        activity_log,
        start_message,
        "INFO"
    )

    # =====================================================
    # HOST AVAILABILITY CHECK
    # =====================================================

    if check_alive:

        try:

            host_alive = is_host_alive(ip)

        except Exception:

            host_alive = True

        if not host_alive:

            warning_message = (
                f"Host {ip} did not respond to ping — "
                f"continuing anyway (ICMP may be blocked)"
            )

            logger.warning(warning_message)

            add_scan_log(
                activity_log,
                warning_message,
                "WARNING"
            )

    # =====================================================
    # CREATE DATABASE SCAN RECORD
    # =====================================================

    scan_id = database.create_scan(
        target,
        ip,
        hostname,
        port_str
    )

    # =====================================================
    # SCAN PORTS
    # =====================================================

    open_ports = []

    start = time.time()

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        future_to_port = {

            executor.submit(
                scan_port,
                ip,
                port,
                timeout
            ): port

            for port in ports
        }

        for future in as_completed(
            future_to_port
        ):

            port = future_to_port[future]

            try:

                is_open = future.result()

            except Exception as e:

                error_message = (
                    f"Error scanning port "
                    f"{port}: {e}"
                )

                logger.error(error_message)

                add_scan_log(
                    activity_log,
                    error_message,
                    "ERROR"
                )

                continue

            # =================================================
            # OPEN PORT
            # =================================================

            if is_open:

                service, risk_level, note = (
                    risk.assess_port(port)
                )

                sys_service = get_service_name(
                    port
                )

                open_ports.append(port)

                # -------------------------------------------------
                # DATABASE
                # -------------------------------------------------

                database.add_result(

                    scan_id,

                    port,

                    "open",

                    service
                    if service != "unknown"
                    else sys_service,

                    risk_level,

                    note
                )

                # -------------------------------------------------
                # TERMINAL LOG
                # -------------------------------------------------

                open_message = (
                    f"Port {port} OPEN — "
                    f"{service} [{risk_level}]"
                )

                logger.info(open_message)

                # -------------------------------------------------
                # WEB UI LOG
                # -------------------------------------------------

                add_scan_log(
                    activity_log,
                    open_message,
                    "OPEN"
                )

    # =====================================================
    # FINISH SCAN
    # =====================================================

    elapsed = time.time() - start

    open_ports.sort()

    database.finish_scan(
        scan_id,
        len(open_ports)
    )

    # =====================================================
    # RISK SUMMARY
    # =====================================================

    summary = risk.summarize_risk(
        open_ports
    )

    # =====================================================
    # ADD SCAN INFORMATION
    # =====================================================

    summary.update({

        "scan_id": scan_id,

        "target": target,

        "ip": ip,

        "hostname": hostname,

        "open_ports": open_ports,

        "duration": format_duration(
            elapsed
        ),

        "ports_scanned": len(ports),

    })

    # =====================================================
    # COMPLETION MESSAGE
    # =====================================================

    complete_message = (

        f"Scan complete: "

        f"{len(open_ports)}/{len(ports)} "

        f"ports open in "

        f"{summary['duration']} "

        f"(highest risk: "

        f"{summary['highest_risk']})"

    )

    logger.info(complete_message)

    add_scan_log(
        activity_log,
        complete_message,
        "INFO"
    )

    return summary


# =========================================================
# TERMINAL SUMMARY
# =========================================================

def print_summary(summary):
    """
    Print scan results in the terminal.
    """

    print(
        f"\nScan Results for "
        f"{summary['target']} "
        f"({summary['ip']})"
    )

    print(
        f"Hostname: "
        f"{summary['hostname']}"
    )

    print(
        f"Ports scanned: "
        f"{summary['ports_scanned']}  |  "
        f"Duration: "
        f"{summary['duration']}"
    )

    print(
        f"Open ports: "
        f"{len(summary['open_ports'])}\n"
    )

    if not summary["details"]:

        print(
            "No open ports found."
        )

        return

    print(
        f"{'PORT':<8}"
        f"{'SERVICE':<15}"
        f"{'RISK':<10}"
        f"NOTE"
    )

    print("-" * 70)

    for detail in summary["details"]:

        print(
            f"{detail['port']:<8}"
            f"{detail['service']:<15}"
            f"{detail['risk_level']:<10}"
            f"{detail['note']}"
        )

    print(
        f"\nHighest overall risk: "
        f"{summary['highest_risk']}"
    )


# =========================================================
# FLASK HOME ROUTE
# =========================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def home():

    # =====================================================
    # DEFAULT VALUES
    # =====================================================

    results = []

    error = None

    scan_logs = []

    summary = None

    # =====================================================
    # HANDLE SCAN FORM
    # =====================================================

    if request.method == "POST":

        try:

            # -------------------------------------------------
            # GET FORM VALUES
            # -------------------------------------------------

            host = request.form.get(
                "host",
                ""
            ).strip()

            start_port_text = request.form.get(
                "start_port",
                "1"
            ).strip()

            end_port_text = request.form.get(
                "end_port",
                "100"
            ).strip()

            # -------------------------------------------------
            # VALIDATE HOST
            # -------------------------------------------------

            if not host:

                raise ValueError(
                    "Please enter a target host."
                )

            # -------------------------------------------------
            # WEB REQUEST LOG
            # -------------------------------------------------

            requested_message = (
                f"Web scan requested: "
                f"{host}"
            )

            logger.info(
                requested_message
            )

            add_scan_log(
                scan_logs,
                requested_message,
                "INFO"
            )

            # -------------------------------------------------
            # CONVERT PORT VALUES
            # -------------------------------------------------

            try:

                start_port = int(
                    start_port_text
                )

                end_port = int(
                    end_port_text
                )

            except ValueError:

                raise ValueError(
                    "Start Port and End Port "
                    "must be numbers."
                )

            # -------------------------------------------------
            # VALIDATE START PORT
            # -------------------------------------------------

            if (
                start_port < 1
                or start_port > 65535
            ):

                raise ValueError(
                    "Start Port must be between "
                    "1 and 65535."
                )

            # -------------------------------------------------
            # VALIDATE END PORT
            # -------------------------------------------------

            if (
                end_port < 1
                or end_port > 65535
            ):

                raise ValueError(
                    "End Port must be between "
                    "1 and 65535."
                )

            # -------------------------------------------------
            # VALIDATE RANGE
            # -------------------------------------------------

            if start_port > end_port:

                raise ValueError(
                    "Start Port cannot be greater "
                    "than End Port."
                )

            # -------------------------------------------------
            # LIMIT WEB SCAN
            # -------------------------------------------------

            if (
                end_port - start_port
            ) > 5000:

                raise ValueError(
                    "For the web interface, "
                    "please scan a maximum of "
                    "5000 ports at a time."
                )

            # -------------------------------------------------
            # CREATE PORT RANGE
            # -------------------------------------------------

            port_range = (
                f"{start_port}-{end_port}"
            )

            # -------------------------------------------------
            # RUN SCANNER
            # -------------------------------------------------

            summary = run_scan(

                target=host,

                port_str=port_range,

                threads=100,

                timeout=1.0,

                check_alive=True,

                activity_log=scan_logs

            )

            # -------------------------------------------------
            # CONVERT OPEN PORTS FOR HTML
            # -------------------------------------------------

            for detail in summary.get(
                "details",
                []
            ):

                results.append({

                    "port": detail["port"],

                    "status": "OPEN",

                    "service": detail["service"],

                    "risk_level": detail["risk_level"],

                    "note": detail["note"]

                })

            # -------------------------------------------------
            # SUCCESS MESSAGE
            # -------------------------------------------------

            success_message = (
                f"Web scan completed "
                f"successfully: {host}"
            )

            logger.info(
                success_message
            )

            add_scan_log(
                scan_logs,
                success_message,
                "INFO"
            )

        except Exception as e:

            # -------------------------------------------------
            # ERROR LOG
            # -------------------------------------------------

            logger.error(
                f"Web scan error: {e}"
            )

            add_scan_log(
                scan_logs,
                f"Web scan error: {e}",
                "ERROR"
            )

            error = str(e)

    # =====================================================
    # RENDER HTML
    # =====================================================

    return render_template(

        "index.html",

        results=results,

        error=error,

        scan_logs=scan_logs,

        summary=summary

    )


# =========================================================
# START FLASK SERVER
# =========================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )

"""Web MTR - a simple web based traceroute using the `mtr` CLI tool."""

import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FutureTimeoutError,
)

from flask import Flask, jsonify, render_template, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = Flask(__name__)

DNS_LOOKUP_TIMEOUT_SECONDS = float(os.environ["DNS_LOOKUP_TIMEOUT_SECONDS"])
LISTEN_ADDR = os.environ["LISTEN_ADDR"]
LISTEN_PORT = int(os.environ["LISTEN_PORT"])
MAX_HOSTNAME_LENGTH = int(os.environ["MAX_HOSTNAME_LENGTH"])
MTR_PING_COUNT = int(os.environ["MTR_PING_COUNT"])
MTR_TIMEOUT_SECONDS = int(os.environ["MTR_TIMEOUT_SECONDS"])

_DNS_EXECUTOR = ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="dns-lookup"
)

_HOSTNAME_LABEL_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1," + str(MAX_HOSTNAME_LENGTH) + r"}(?<!-)$"
)


_LOG_SANITIZE_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


def _sanitize_for_log(value: str) -> str:
    """Strip control/newline characters from untrusted input before logging
    it, to prevent log injection/forging (CWE-117)."""
    return _LOG_SANITIZE_RE.sub("", value)


def get_client_ip() -> str:
    """Best-effort lookup of the caller's IP address, honouring reverse proxies.

    Note: X-Forwarded-For is attacker-controlled unless this app sits behind a
    trusted reverse proxy that overwrites/strips it. It is used here only for
    display/logging convenience, never for access control."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        caller_ip = forwarded_for.split(",")[0].strip()
        logging.info(
            "Client IP from X-Forwarded-For: %s", _sanitize_for_log(caller_ip)
        )
        return caller_ip
    logging.info(
        "Client IP from remote_addr: %s",
        _sanitize_for_log(request.remote_addr or ""),
    )
    return request.remote_addr or ""


def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        logging.error("Invalid hostname length: %s", hostname)
        return False
    labels = hostname.rstrip(".").split(".")
    match = all(_HOSTNAME_LABEL_RE.match(label) for label in labels)
    if not match:
        logging.error("Invalid hostname format: %s", hostname)
    else:
        logging.info("Valid hostname: %s", hostname)
    return match


def is_valid_target(target: str) -> bool:
    # Ensure target only contains valid characters to prevent command injection
    if not re.match(r"^[A-Za-z0-9\.\-:]+$", target):
        logging.error("Invalid target characters: %s", target)
        return False

    if not target or len(target) > MAX_HOSTNAME_LENGTH:
        logging.error("Invalid target length: %s", target)
        return False
    try:
        ipaddress.ip_address(target)
        logging.info("Valid IP address target: %s", target)
        return True
    except ValueError:
        pass
    return is_valid_hostname(target)


def _reverse_dns_lookup(ip_address: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        logging.info("Reverse DNS lookup for %s: %s", ip_address, hostname)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        logging.error("Reverse DNS lookup failed for %s", ip_address)
        return ""


def annotate_dns_names(hubs: list[dict]) -> None:
    """Add a best-effort reverse DNS "dns_name" field to each hop, in place."""
    pending = {}
    for index, hub in enumerate(hubs):
        host = hub.get("host") or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            hub["dns_name"] = ""
            continue
        pending[index] = _DNS_EXECUTOR.submit(_reverse_dns_lookup, host)

    for index, future in pending.items():
        try:
            hubs[index]["dns_name"] = future.result(
                timeout=DNS_LOOKUP_TIMEOUT_SECONDS
            )
        except FutureTimeoutError:
            logging.error(
                "Reverse DNS lookup timed out for %s",
                hubs[index].get("host") or "",
            )
            hubs[index]["dns_name"] = ""


@app.route("/")
def index():
    return render_template("index.html", client_ip=get_client_ip())


@app.route("/traceroute")
def traceroute():
    target = request.args.get("target", "").strip()
    logging.info(
        "Received traceroute request from %s to %s",
        _sanitize_for_log(get_client_ip()),
        _sanitize_for_log(target),
    )

    if not is_valid_target(target):
        return (
            jsonify({"error": "Please enter a valid IP address or hostname."}),
            400,
        )

    try:
        logging.info("Running traceroute to target: %s", target)
        result = subprocess.run(
            ["mtr", "-j", "-n", "-z", "-c", str(MTR_PING_COUNT), target],
            capture_output=True,
            text=True,
            timeout=MTR_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logging.error(
            "Traceroute to %s timed out after %s seconds",
            target,
            MTR_TIMEOUT_SECONDS,
        )
        return jsonify({"error": "Traceroute timed out."}), 504
    except FileNotFoundError:
        logging.error("mtr command not found on the server.")
        return (
            jsonify(
                {"error": "The mtr command is not available on the server."}
            ),
            500,
        )

    if result.returncode != 0:
        logging.error(
            "Traceroute to %s failed: %s", target, result.stderr.strip()
        )
        return jsonify({"error": "Traceroute failed."}), 502

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logging.error(
            "Failed to parse traceroute output for target %s: %s",
            target,
            result.stdout,
        )
        return jsonify({"error": "Failed to parse traceroute output."}), 502

    annotate_dns_names(data.get("report", {}).get("hubs", []))

    logging.info("Traceroute to %s completed successfully.", target)
    return jsonify(data)


if __name__ == "__main__":
    app.run(host=LISTEN_ADDR, port=LISTEN_PORT, debug=False)

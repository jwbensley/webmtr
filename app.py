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
NAT64 = str(os.environ["NAT64"])

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
    except socket.herror, socket.gaierror, OSError:
        logging.error("Reverse DNS lookup failed for %s", ip_address)
        return ""


_NAT64_SUPPORTED_PREFIX_LENGTHS = (32, 40, 48, 56, 64, 96)


def _embed_ipv4_in_nat64(ipv4_str: str, nat64_prefix: str) -> str | None:
    """Embed an IPv4 address into a NAT64 prefix per RFC 6052 to build the
    IPv6 address mtr should actually target on an IPv6-only host."""
    try:
        v4 = ipaddress.IPv4Address(ipv4_str)
        prefix_net = ipaddress.IPv6Network(nat64_prefix, strict=False)
    except ValueError:
        logging.error(
            "Invalid NAT64 prefix or IPv4 address: %s / %s",
            nat64_prefix,
            ipv4_str,
        )
        return None

    prefix_len = prefix_net.prefixlen
    if prefix_len not in _NAT64_SUPPORTED_PREFIX_LENGTHS:
        logging.error("Unsupported NAT64 prefix length: /%d", prefix_len)
        return None

    prefix_bytes = prefix_net.network_address.packed
    v4_bytes = v4.packed

    if prefix_len == 96:
        # prefix(96 bits) + v4(32 bits), no reserved 'u' octet needed.
        result_bytes = prefix_bytes[:12] + v4_bytes
    else:
        # RFC 6052 reserves a zero octet at bits 64-71 ('u'), so the v4
        # bits after that point are shifted right by one byte.
        prefix_octets = prefix_len // 8
        combined = bytearray(15)
        combined[:prefix_octets] = prefix_bytes[:prefix_octets]
        combined[prefix_octets : prefix_octets + 4] = v4_bytes
        result_bytes = bytes(combined[:8]) + b"\x00" + bytes(combined[8:15])

    nat64_address = str(ipaddress.IPv6Address(result_bytes))
    logging.info(
        "NAT64-mapped %s to %s using prefix %s",
        ipv4_str,
        nat64_address,
        nat64_prefix,
    )
    return nat64_address


def _resolve_hostname(hostname: str, family: int) -> str | None:
    """Resolve a hostname to a single address of the given family, with a
    timeout, returning None if no such record exists or lookup times out."""

    def _lookup() -> str:
        infos = socket.getaddrinfo(hostname, None, family)
        return str(infos[0][4][0])

    future = _DNS_EXECUTOR.submit(_lookup)
    try:
        return future.result(timeout=DNS_LOOKUP_TIMEOUT_SECONDS)
    except FutureTimeoutError:
        logging.error("DNS lookup for %s timed out", hostname)
        return None
    except socket.gaierror, OSError:
        return None


def resolve_nat64_target(target: str) -> tuple[str | None, str | None]:
    """Work out the address mtr should actually target given NAT64.

    On an IPv6-only host, IPv4 destinations must be reached via a NAT64
    prefix. If NAT64 is configured (the NAT64 env var holds a valid IPv6
    prefix):
      - an IPv4 target is embedded directly into the NAT64 prefix.
      - an IPv6 target is used unchanged.
      - a hostname target has its AAAA record resolved first (used
        unchanged if found); if there is no AAAA record, its A record is
        resolved and embedded into the NAT64 prefix.
    If NAT64 is not configured, the target is returned unchanged.

    Returns a (mtr_target, error_message) tuple; exactly one is None.
    """
    nat64_prefix = NAT64.strip()
    if not nat64_prefix:
        return target, None

    try:
        ipaddress.IPv6Network(nat64_prefix, strict=False)
    except ValueError:
        logging.error(
            "NAT64 env var is not a valid IPv6 prefix: %s", nat64_prefix
        )
        return target, None

    try:
        parsed = ipaddress.ip_address(target)
    except ValueError:
        parsed = None

    if isinstance(parsed, ipaddress.IPv4Address):
        mapped = _embed_ipv4_in_nat64(target, nat64_prefix)
        if mapped is None:
            return None, "Failed to map IPv4 address via NAT64."
        return mapped, None

    if isinstance(parsed, ipaddress.IPv6Address):
        return target, None

    # target is a hostname: prefer a native AAAA record over NAT64.
    aaaa_address = _resolve_hostname(target, socket.AF_INET6)
    if aaaa_address:
        return aaaa_address, None

    a_address = _resolve_hostname(target, socket.AF_INET)
    if not a_address:
        return None, "Could not resolve hostname to an IPv4 or IPv6 address."

    mapped = _embed_ipv4_in_nat64(a_address, nat64_prefix)
    if mapped is None:
        return None, "Failed to map IPv4 address via NAT64."
    return mapped, None


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
    return render_template("index.html")


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

    # On an IPv6-only host, IPv4 destinations (and hostnames without a AAAA
    # record) must be reached via a NAT64 prefix; see resolve_nat64_target().
    mtr_target, nat64_error = resolve_nat64_target(target)
    if mtr_target is None:
        logging.error(
            "NAT64 resolution failed for %s: %s", target, nat64_error
        )
        return jsonify({"error": nat64_error}), 502

    try:
        logging.info(
            "Running traceroute to target: %s (%s)", target, mtr_target
        )
        result = subprocess.run(
            ["mtr", "-j", "-n", "-z", "-c", str(MTR_PING_COUNT), mtr_target],
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

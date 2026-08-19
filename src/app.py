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
from typing import Any

import dns.exception
import dns.resolver
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
NAT64 = os.environ["NAT64"]

_DNS_EXECUTOR = ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="dns-lookup"
)

HOSTNAME_LABEL_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1," + str(MAX_HOSTNAME_LENGTH) + r"}(?<!-)$"
)

LOG_SANITIZE_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")

NAT64_SUPPORTED_PREFIX_LENGTHS = (32, 40, 48, 56, 64, 96)


def sanitize_for_log(value: str) -> str:
    """Strip control/newline characters from untrusted input before logging
    it, to prevent log injection/forging (CWE-117)."""
    return LOG_SANITIZE_RE.sub("", value)


def get_client_ip() -> str:
    """Best-effort lookup of the caller's IP address, honouring reverse proxies.

    Note: X-Forwarded-For is attacker-controlled unless this app sits behind a
    trusted reverse proxy that overwrites/strips it. It is used here only for
    display/logging convenience, never for access control."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        caller_ip = forwarded_for.split(",")[0].strip()
        logging.info(
            "Client IP from X-Forwarded-For: %s", sanitize_for_log(caller_ip)
        )
        return caller_ip
    logging.info(
        "Client IP from remote_addr: %s",
        sanitize_for_log(request.remote_addr or ""),
    )
    return request.remote_addr or ""


def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        logging.error("Invalid hostname length: %s", hostname)
        return False
    labels = hostname.rstrip(".").split(".")
    match = all(HOSTNAME_LABEL_RE.match(label) for label in labels)
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


def reverse_dns_lookup(ip_address: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        logging.info("Reverse DNS lookup for %s: %s", ip_address, hostname)
        return hostname
    except socket.herror, socket.gaierror, OSError:
        logging.error("Reverse DNS lookup failed for %s", ip_address)
        return ""


def _extract_ipv4_from_nat64(ipv6_str: str, nat64_prefix: str) -> str | None:
    """If ipv6_str is a NAT64-mapped address inside nat64_prefix, return the
    IPv4 address embedded in it per RFC 6052; otherwise return None."""

    try:
        v6_address = ipaddress.IPv6Address(ipv6_str)
        prefix_net = ipaddress.IPv6Network(nat64_prefix, strict=False)
    except ValueError:
        logging.error(
            "Invalid IPv6 address or NAT64 prefix: %s, %s",
            sanitize_for_log(ipv6_str),
            sanitize_for_log(nat64_prefix),
        )
        return None

    prefix_len = prefix_net.prefixlen
    if prefix_len not in NAT64_SUPPORTED_PREFIX_LENGTHS:
        return None
    if v6_address not in prefix_net:
        return None

    v6_bytes = v6_address.packed
    if prefix_len == 96:
        # prefix(96 bits) + v4(32 bits), no reserved 'u' octet.
        v4_bytes = v6_bytes[12:16]
    else:
        # RFC 6052 reserves a zero octet at bits 64-71 ('u'), so skip it
        # before extracting the embedded v4 bits.
        prefix_octets = prefix_len // 8
        combined = v6_bytes[:8] + v6_bytes[9:16]
        v4_bytes = combined[prefix_octets : prefix_octets + 4]

    ipv4 = str(ipaddress.IPv4Address(v4_bytes))
    logging.info(
        f"Extracted IPv4 {ipv4} from NAT64-mapped IPv6 {ipv6_str} with prefix {nat64_prefix}"
    )
    return ipv4


def replace_nat64_names(data: dict[str, Any], nat64_prefix: str) -> None:
    """Replace each hop's NAT64-mapped IPv6 "host" with the IPv4 address it
    embeds, in place, so results are shown in IPv4 form."""
    prefix = (nat64_prefix or "").strip()
    if not prefix:
        return
    try:
        ipaddress.IPv6Network(prefix, strict=False)
    except ValueError:
        logging.error(
            "NAT64 env var is not a valid IPv6 prefix: %s",
            sanitize_for_log(prefix),
        )
        return

    for hub in data.get("report", {}).get("hubs", []):
        host = hub.get("host") or ""
        ipv4_address = _extract_ipv4_from_nat64(host, prefix)
        if ipv4_address is not None:
            hub["host"] = ipv4_address


def _asn_query_name(ip_address: str) -> str | None:
    """Build the Team Cymru IP-to-ASN DNS query name for an IP address."""
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    if isinstance(parsed, ipaddress.IPv4Address):
        octets = ip_address.split(".")
        return ".".join(reversed(octets)) + ".origin.asn.cymru.com"

    # IPv6: nibble-reversed hex digits of the full 128-bit address.
    hex_digits = format(int(parsed), "032x")
    return ".".join(reversed(hex_digits)) + ".origin6.asn.cymru.com"


def _lookup_asn(ip_address: str) -> str | None:
    """Query Team Cymru's IP-to-ASN DNS service for the origin AS of an IP
    address, returning e.g. "AS15169", or None if it couldn't be found."""
    query_name = _asn_query_name(ip_address)
    if query_name is None:
        return None

    try:
        answers = dns.resolver.resolve(
            query_name, "TXT", lifetime=DNS_LOOKUP_TIMEOUT_SECONDS
        )
    except dns.exception.DNSException:
        logging.error("ASN lookup failed for %s", sanitize_for_log(ip_address))
        return None

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("ascii", errors="replace")
        # Response format: "ASN | BGP Prefix | CC | Registry | Allocated"
        # ASN field may list multiple origin ASNs space-separated; use the
        # first one.
        asn_field = txt.split("|", 1)[0].strip()
        first_asn = asn_field.split()[0] if asn_field else ""
        if first_asn.isdigit():
            return f"AS{first_asn}"

    return None


def annotate_asns(hubs: list[dict[str, Any]]) -> None:
    """Fill in any missing "ASN" ("AS???") fields via a best-effort Team
    Cymru IP-to-ASN DNS lookup, in place."""
    pending = {}
    for index, hub in enumerate(hubs):
        if hub.get("ASN") != "AS???":
            continue
        host = hub.get("host") or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        pending[index] = _DNS_EXECUTOR.submit(_lookup_asn, host)

    for index, future in pending.items():
        try:
            asn = future.result(timeout=DNS_LOOKUP_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            logging.error(
                "ASN lookup timed out for %s", hubs[index].get("host") or ""
            )
            continue
        if asn:
            hubs[index]["ASN"] = asn


def annotate_dns_names(hubs: list[dict[str, Any]]) -> None:
    """Add a best-effort reverse DNS "dns_name" field to each hop, in place."""
    pending = {}
    for index, hub in enumerate(hubs):
        host = hub.get("host") or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            hub["dns_name"] = ""
            continue
        pending[index] = _DNS_EXECUTOR.submit(reverse_dns_lookup, host)

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


def convert_ipv4_to_nat64(ipv4_str: str, nat64_prefix: str) -> str:
    """Convert an IPv4 address string to a NAT64-mapped IPv6 address string
    using the given NAT64 prefix, per RFC 6052."""

    logging.info(
        "Converting IPv4 %s to NAT64-mapped IPv6 using prefix %s",
        sanitize_for_log(ipv4_str),
        sanitize_for_log(nat64_prefix),
    )

    try:
        ipv4 = ipaddress.IPv4Address(ipv4_str)
        prefix_net = ipaddress.IPv6Network(nat64_prefix, strict=False)
    except ValueError:
        logging.error(
            "Invalid IPv4 address or NAT64 prefix: %s, %s",
            sanitize_for_log(ipv4_str),
            sanitize_for_log(nat64_prefix),
        )
        return ipv4_str

    prefix_len = prefix_net.prefixlen
    if prefix_len not in NAT64_SUPPORTED_PREFIX_LENGTHS:
        logging.error(
            "NAT64 prefix length is not supported: %s",
            sanitize_for_log(nat64_prefix),
        )
        return ipv4_str

    # Embed the IPv4 address into the NAT64 prefix.
    v6_bytes = bytearray(prefix_net.network_address.packed)
    if prefix_len == 96:
        v6_bytes[12:16] = ipv4.packed
    else:
        # RFC 6052 reserves a zero octet at bits 64-71 ('u'), so skip it
        # before embedding the IPv4 bits.
        v6_bytes[8:12] = b"\x00" + ipv4.packed

    nat64_address = str(ipaddress.IPv6Address(bytes(v6_bytes)))
    logging.info(
        "Converted IPv4 %s to NAT64-mapped IPv6 %s",
        sanitize_for_log(ipv4_str),
        sanitize_for_log(nat64_address),
    )
    return nat64_address


def resolve_destination_ip(target: str) -> str:
    """Best-effort resolution of the human-facing destination address: if
    target is already a literal IP address, return it unchanged; if it's a
    hostname, resolve it via forward DNS to the address mtr will likely
    reach, falling back to the original hostname if resolution fails."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        logging.error(
            "Forward DNS lookup failed for %s", sanitize_for_log(target)
        )
        return target
    if not infos:
        return target
    return infos[0][4][0]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/traceroute")
def traceroute():
    target = request.args.get("target", "").strip()
    logging.info(
        "Received traceroute request from %s to %s",
        sanitize_for_log(get_client_ip()),
        sanitize_for_log(target),
    )

    """
    If using NAT64 convert a literal IPv4 address to a NAT64-mapped IPv6 address
    """
    if NAT64:
        mtr_target = convert_ipv4_to_nat64(target, NAT64)
    else:
        mtr_target = target

    if not is_valid_target(mtr_target):
        return (
            jsonify({"error": "Please enter a valid IP address or hostname."}),
            400,
        )

    # Resolve the human-facing destination address in parallel with mtr, so
    # the frontend can show what we were trying to reach even if the final
    # hop is never reached.
    destination_future = _DNS_EXECUTOR.submit(resolve_destination_ip, target)

    try:
        cmd = ["mtr", "-j", "-n", "-z", "-c", str(MTR_PING_COUNT), mtr_target]
        logging.info(
            "Running traceroute to target: %s (%s)",
            sanitize_for_log(target),
            sanitize_for_log(mtr_target),
        )
        logging.info("Executing command: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MTR_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        msg = (
            f"Traceroute to {sanitize_for_log(mtr_target)} timed out after "
            f"{MTR_TIMEOUT_SECONDS} seconds"
        )
        logging.error(msg)
        return jsonify({"error": msg}), 504
    except FileNotFoundError:
        msg = "The mtr command is not available on the server."
        logging.error(msg)
        return (
            jsonify({"error": msg}),
            500,
        )

    if result.returncode != 0:
        msg = (
            f"Traceroute to {sanitize_for_log(target)} failed with return code "
            f"{result.returncode}: {sanitize_for_log(result.stderr.strip())}"
        )
        logging.error(msg)
        return jsonify({"error": msg}), 502

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        msg = (
            f"Failed to parse traceroute output for target {sanitize_for_log(target)}: "
            f"{sanitize_for_log(result.stdout)}"
        )
        logging.error(msg)
        return jsonify({"error": msg}), 502

    """
    If NAT64 is used, replace the NAT64-mapped IPv6 addresses in the traceroute output
    with their corresponding IPv4 addresses, so that reverse DNS and ASN lookups can be
    performed against the IPv4 addresses.
    """
    if NAT64:
        replace_nat64_names(data, NAT64)
        annotate_asns(data.get("report", {}).get("hubs", []))

    annotate_dns_names(data.get("report", {}).get("hubs", []))

    try:
        data["destination"] = destination_future.result(
            timeout=DNS_LOOKUP_TIMEOUT_SECONDS
        )
    except FutureTimeoutError:
        logging.error(
            "Destination DNS resolution timed out for %s",
            sanitize_for_log(target),
        )
        data["destination"] = target

    logging.info("Traceroute to %s completed successfully.", target)
    return jsonify(data)


if __name__ == "__main__":
    app.run(host=LISTEN_ADDR, port=LISTEN_PORT, debug=False)

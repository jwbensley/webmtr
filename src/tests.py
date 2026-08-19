import os
import socket
from unittest.mock import MagicMock, patch

"""
Environment variables that app.py reads at import time must be set before
`app` is imported, since it reads them via `os.environ[...]` with no
defaults.
"""
os.environ.setdefault("DNS_LOOKUP_TIMEOUT_SECONDS", "2")
os.environ.setdefault("LISTEN_ADDR", "0.0.0.0")
os.environ.setdefault("LISTEN_PORT", "8371")
os.environ.setdefault("MAX_HOSTNAME_LENGTH", "254")
os.environ.setdefault("MTR_PING_COUNT", "5")
os.environ.setdefault("MTR_TIMEOUT_SECONDS", "30")
os.environ.setdefault("NAT64", "")

import pytest

import app


@pytest.fixture()
def client():
    app.app.testing = True
    return app.app.test_client()


# --- sanitize_for_log -------------------------------------------------


def test_sanitize_for_log_strips_control_characters():
    assert (
        app.sanitize_for_log("host\r\nInjected: true") == "hostInjected: true"
    )


def test_sanitize_for_log_leaves_normal_text_unchanged():
    assert app.sanitize_for_log("example.com") == "example.com"


# --- get_client_ip ------------------------------------------------------


def test_get_client_ip_prefers_x_forwarded_for():
    with app.app.test_request_context(
        "/", headers={"X-Forwarded-For": "203.0.113.5, 10.0.0.1"}
    ):
        assert app.get_client_ip() == "203.0.113.5"


def test_get_client_ip_falls_back_to_remote_addr():
    with app.app.test_request_context(
        "/", environ_base={"REMOTE_ADDR": "127.0.0.1"}
    ):
        assert app.get_client_ip() == "127.0.0.1"


# --- is_valid_hostname ---------------------------------------------------


@pytest.mark.parametrize(
    "hostname",
    ["example.com", "sub.example.com", "a", "host-name.example."],
)
def test_is_valid_hostname_accepts_valid_names(hostname):
    assert app.is_valid_hostname(hostname) is True


@pytest.mark.parametrize(
    "hostname",
    ["", "-badstart.com", "badend-.com", "a" * 300],
)
def test_is_valid_hostname_rejects_invalid_names(hostname):
    assert app.is_valid_hostname(hostname) is False


# --- is_valid_target -------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "2001:4860:4860::8888", "example.com"],
)
def test_is_valid_target_accepts_valid_targets(target):
    assert app.is_valid_target(target) is True


@pytest.mark.parametrize(
    "target",
    ["", "-c", "; rm -rf /", "example.com; ls", "a" * 300],
)
def test_is_valid_target_rejects_invalid_targets(target):
    assert app.is_valid_target(target) is False


# --- resolve_destination_ip ------------------------------------------------


def test_resolve_destination_ip_returns_literal_ip_unchanged():
    assert app.resolve_destination_ip("8.8.8.8") == "8.8.8.8"


def test_resolve_destination_ip_resolves_hostname():
    with patch.object(
        app.socket,
        "getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 0))],
    ):
        assert app.resolve_destination_ip("example.com") == "93.184.216.34"


def test_resolve_destination_ip_falls_back_to_hostname_on_failure():
    with patch.object(app.socket, "getaddrinfo", side_effect=socket.gaierror):
        assert (
            app.resolve_destination_ip("nonexistent.invalid")
            == "nonexistent.invalid"
        )


# --- reverse_dns_lookup ------------------------------------------------


def test_reverse_dns_lookup_returns_hostname_on_success():
    with patch.object(
        app.socket,
        "gethostbyaddr",
        return_value=("host.example.com", [], ["8.8.8.8"]),
    ):
        assert app.reverse_dns_lookup("8.8.8.8") == "host.example.com"


def test_reverse_dns_lookup_returns_empty_string_on_failure():
    with patch.object(app.socket, "gethostbyaddr", side_effect=socket.herror):
        assert app.reverse_dns_lookup("8.8.8.8") == ""


# --- NAT64 helpers -------------------------------------------------------


def test_convert_ipv4_to_nat64_rfc6052_example():
    assert (
        app.convert_ipv4_to_nat64("8.8.8.8", "64:ff9b::/96")
        == "64:ff9b::808:808"
    )


def test_convert_ipv4_to_nat64_invalid_prefix_returns_original():
    assert app.convert_ipv4_to_nat64("8.8.8.8", "not-a-prefix") == "8.8.8.8"


def test_extract_ipv4_from_nat64_round_trips():
    assert (
        app._extract_ipv4_from_nat64("64:ff9b::808:808", "64:ff9b::/96")
        == "8.8.8.8"
    )


def test_extract_ipv4_from_nat64_returns_none_outside_prefix():
    assert app._extract_ipv4_from_nat64("2001:db8::1", "64:ff9b::/96") is None


def test_replace_nat64_names_replaces_matching_hosts():
    data = {
        "report": {
            "hubs": [{"host": "64:ff9b::808:808"}, {"host": "10.0.0.1"}]
        }
    }
    app.replace_nat64_names(data, "64:ff9b::/96")
    assert data["report"]["hubs"][0]["host"] == "8.8.8.8"
    assert data["report"]["hubs"][1]["host"] == "10.0.0.1"


def test_replace_nat64_names_noop_when_prefix_blank():
    data = {"report": {"hubs": [{"host": "64:ff9b::808:808"}]}}
    app.replace_nat64_names(data, "")
    assert data["report"]["hubs"][0]["host"] == "64:ff9b::808:808"


# --- ASN lookups ---------------------------------------------------------


def test_asn_query_name_ipv4():
    assert app._asn_query_name("8.8.8.8") == "8.8.8.8.origin.asn.cymru.com"


def test_asn_query_name_ipv6():
    name = app._asn_query_name("2001:4860:4860::8888")
    assert name is not None
    assert name.endswith(".origin6.asn.cymru.com")


def _make_txt_answer(text: str):
    rdata = MagicMock()
    rdata.strings = [text.encode("ascii")]
    return [rdata]


def test_lookup_asn_parses_first_asn_from_response():
    answer = _make_txt_answer("15169 | 8.8.8.0/24 | US | arin | 2014-03-14")
    with patch.object(app.dns.resolver, "resolve", return_value=answer):
        assert app._lookup_asn("8.8.8.8") == "AS15169"


def test_lookup_asn_returns_none_on_dns_exception():
    with patch.object(
        app.dns.resolver, "resolve", side_effect=app.dns.exception.DNSException
    ):
        assert app._lookup_asn("8.8.8.8") is None


def test_annotate_asns_fills_in_missing_asn():
    hubs = [
        {"host": "8.8.8.8", "ASN": "AS???"},
        {"host": "10.0.0.1", "ASN": "AS64500"},
    ]
    with patch.object(app, "_lookup_asn", return_value="AS15169"):
        app.annotate_asns(hubs)
    assert hubs[0]["ASN"] == "AS15169"
    assert hubs[1]["ASN"] == "AS64500"


def test_annotate_dns_names_sets_dns_name_field():
    hubs = [{"host": "8.8.8.8"}, {"host": "not-an-ip"}]
    with patch.object(app, "reverse_dns_lookup", return_value="dns.google"):
        app.annotate_dns_names(hubs)
    assert hubs[0]["dns_name"] == "dns.google"
    assert hubs[1]["dns_name"] == ""


# --- /traceroute route -----------------------------------------------------


MTR_OUTPUT = '{"report": {"hubs": [{"host": "8.8.8.8", "ASN": "AS???"}]}}'


def _mock_completed_process(stdout="", stderr="", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def test_traceroute_rejects_invalid_target(client):
    response = client.get("/traceroute", query_string={"target": "; rm -rf /"})
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_traceroute_success(client):
    with (
        patch.object(
            app.subprocess,
            "run",
            return_value=_mock_completed_process(stdout=MTR_OUTPUT),
        ) as mock_run,
        patch.object(app, "reverse_dns_lookup", return_value="dns.google"),
    ):
        response = client.get(
            "/traceroute", query_string={"target": "8.8.8.8"}
        )

    assert response.status_code == 200
    mock_run.assert_called_once()
    data = response.get_json()
    hub = data["report"]["hubs"][0]
    assert hub["dns_name"] == "dns.google"
    assert data["destination"] == "8.8.8.8"


def test_traceroute_success_with_nat64_annotates_asn(client):
    with (
        patch.object(app, "NAT64", "64:ff9b::/96"),
        patch.object(
            app.subprocess,
            "run",
            return_value=_mock_completed_process(stdout=MTR_OUTPUT),
        ),
        patch.object(app, "reverse_dns_lookup", return_value="dns.google"),
        patch.object(app, "_lookup_asn", return_value="AS15169"),
    ):
        response = client.get(
            "/traceroute", query_string={"target": "8.8.8.8"}
        )

    assert response.status_code == 200
    hub = response.get_json()["report"]["hubs"][0]
    assert hub["ASN"] == "AS15169"


def test_traceroute_handles_timeout(client):
    with patch.object(
        app.subprocess,
        "run",
        side_effect=app.subprocess.TimeoutExpired(cmd="mtr", timeout=30),
    ):
        response = client.get(
            "/traceroute", query_string={"target": "8.8.8.8"}
        )
    assert response.status_code == 504


def test_traceroute_handles_missing_mtr_binary(client):
    with patch.object(app.subprocess, "run", side_effect=FileNotFoundError):
        response = client.get(
            "/traceroute", query_string={"target": "8.8.8.8"}
        )
    assert response.status_code == 500


def test_traceroute_handles_nonzero_return_code(client):
    with patch.object(
        app.subprocess,
        "run",
        return_value=_mock_completed_process(stderr="boom", returncode=1),
    ):
        response = client.get(
            "/traceroute", query_string={"target": "8.8.8.8"}
        )
    assert response.status_code == 502


def test_traceroute_handles_invalid_json_output(client):
    with patch.object(
        app.subprocess,
        "run",
        return_value=_mock_completed_process(stdout="not json"),
    ):
        response = client.get(
            "/traceroute", query_string={"target": "8.8.8.8"}
        )
    assert response.status_code == 502


def test_traceroute_includes_resolved_destination_for_hostname(client):
    with (
        patch.object(
            app.subprocess,
            "run",
            return_value=_mock_completed_process(stdout=MTR_OUTPUT),
        ),
        patch.object(app, "reverse_dns_lookup", return_value="dns.google"),
        patch.object(
            app.socket,
            "getaddrinfo",
            return_value=[(None, None, None, None, ("8.8.8.8", 0))],
        ),
    ):
        response = client.get(
            "/traceroute", query_string={"target": "dns.google"}
        )

    assert response.status_code == 200
    assert response.get_json()["destination"] == "8.8.8.8"

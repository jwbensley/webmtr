# Web MTR

## Overview

A simple web based traceroute:

* A Python application runs the CLI command `mtr` and returns the results in JSON format.
* An ICMP/v6 traceroute is performed.
* Running in a NAT64 (IPv6-only) environment is supported if you don't have a dual stack environment!
* The JSON output from `mtr` is parsed and displayed by a web UI (you can call the API directly to get JSON output).
* UV is used to manage Python dependencies, virtual environments, and to run tests.
* Gunicorn is used to run the web application and control the number of worker processes.
* All application settings are defined in the [.env](.env) file.
* The application runs inside Docker (the capability `NET_RAW` is required for `mtr` to have ICMP privileges).

[![Web MTR UI](screenshot.png)](screenshot.png)

An example from a NAT64 (IPv6-only!) host.

## Usage

```text
# Start the container
docker compose up -d

# Logs are sent to a file
tail -f logs/access.log
```

GET JSON output by calling the API directly:

```text
curl -s http://localhost:8371/traceroute?target=8.8.8.8 | jq
```

Open a browser to <http://localhost:8371> to use the UI.

## Bindings

If you want to bind to a specific IPv6 address, set the `LISTEN_ADDR` env var using square bracket syntax: `LISTEN_ADDR=[fe80::1122:3344:5566:7788]`

## NAT64

If running on an IPv6 only host which uses NAT64 to provide IPv4 connectivity, ensure the `NAT64` env var contains the prefix of the NAT64 network, e.g. `NAT64=64:ff9b::/96`. Leave this var defined but empty if the host has native IPv4 connectivity.

With this env var set:

* When an IPv4 address is entered as the target, it will be converted to a NAT64 address and the traceroute will be performed using that address.
* When a traceroute is run to a NAT64 prefix (due to an IPv4 literal target or DNS64) the IPv4 addresses of each hop in the results are extracted from the `mtr` output and displayed as IPv4 addresses, along with their reverse DNS lookup result, and the ASN of the IPv4 address; rather than the NAT64 addresses (which have no reverse DNS or ASN information).

## Tests

```text
uv run pytest src/tests.py -q
```

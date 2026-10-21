#!/usr/bin/env python3
"""One-request, read-only HTTPS header check; this cannot confirm PHP2Shell."""

import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.parse

TIMEOUT_SECONDS = 5
MAX_URL_LENGTH = 2048
PHP_VERSION = re.compile(
    r"\bPHP\s*/?\s*(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?)\b",
    re.IGNORECASE,
)


class CheckInputError(Exception):
    """The supplied URL is invalid or does not resolve to a public host."""


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, timeout):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def validate_url(url):
    if len(url) > MAX_URL_LENGTH or any(ord(character) < 32 for character in url):
        raise CheckInputError("URL is invalid or too long")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CheckInputError("URL is malformed") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise CheckInputError("provide an absolute HTTPS URL on the default port, without credentials or a fragment")
    host = parsed.hostname
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise CheckInputError("host resolution failed") from exc
        addresses = list(dict.fromkeys(entry[4][0] for entry in resolved))
        if not addresses:
            raise CheckInputError("host did not resolve")
        try:
            parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
        except ValueError as exc:
            raise CheckInputError("host resolved to an invalid address") from exc
        if any(not address.is_global for address in parsed_addresses):
            raise CheckInputError("only publicly routable hosts are allowed")
        address = addresses[0]
    else:
        if not literal.is_global:
            raise CheckInputError("only publicly routable hosts are allowed")
        address = str(literal)
    return parsed, address


def _safe_header(value):
    if value is None:
        return None
    return "".join(character if character.isprintable() else " " for character in value)[:256].strip()


def _report(parsed, status, headers=None, http_status=None):
    headers = headers or {}
    server = _safe_header(headers.get("Server"))
    powered_by = _safe_header(headers.get("X-Powered-By"))
    php_version = None
    for value in (powered_by, server):
        if value:
            match = PHP_VERSION.search(value)
            if match:
                php_version = match.group(1)
                break
    if status == "http_response":
        status = "php_version_disclosed" if php_version else "no_php_version_disclosed"
    return {
        "tool": "php2shell-http-check",
        "schema_version": 1,
        "host": parsed.hostname,
        "status": status,
        "http_status": http_status,
        "server_header": server,
        "x_powered_by_header": powered_by,
        "php_version_disclosed": php_version,
        "vulnerability_status": "not_determined",
        "exploitation_attempted": False,
        "limitations": [
            "This sends one ordinary HTTPS GET and inspects response headers only.",
            "Public HTTP headers cannot establish the PHP runtime serving a specific application or its vendor backport status.",
            "A disclosed PHP version is not proof that PHP2Shell is exploitable; an undisclosed version is not evidence of safety.",
            "No exploit payload, login, redirect follow-up, or application response-body inspection is performed.",
        ],
    }


def check_url(url, connection_factory=None):
    parsed, address = validate_url(url)
    connection_factory = connection_factory or PinnedHTTPSConnection
    connection = connection_factory(parsed.hostname, address, TIMEOUT_SECONDS)
    response = None
    try:
        connection.connect()
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": "php2shell-http-check/1.0 (read-only header check)",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
    except (OSError, http.client.HTTPException, TimeoutError):
        connection.close()
        return _report(parsed, "connection_failed")
    try:
        status = response.getcode()
        headers = dict(response.getheaders())
        if 300 <= status < 400:
            return _report(parsed, "redirect_not_followed", headers, status)
        return _report(parsed, "http_response", headers, status)
    finally:
        response.close()
        connection.close()


def _human_report(report):
    lines = [
        "PHP2Shell public-response check (read-only; not a vulnerability scanner)",
        "Host: " + report["host"],
        "Observation: " + report["status"],
        "HTTP status: " + (str(report["http_status"]) if report["http_status"] is not None else "unavailable"),
    ]
    if report["server_header"]:
        lines.append("Server header: " + report["server_header"])
    if report["x_powered_by_header"]:
        lines.append("X-Powered-By header: " + report["x_powered_by_header"])
    if report["php_version_disclosed"]:
        lines.append("Advertised PHP version: " + report["php_version_disclosed"])
    lines.extend((
        "PHP2Shell vulnerability status: not determined",
        "No exploit or login was attempted; redirects were not followed.",
        "A disclosed or hidden version cannot confirm vulnerable or patched status.",
    ))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="one explicitly supplied HTTPS URL on the default port")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    args = parser.parse_args(argv)
    try:
        report = check_url(args.url)
    except CheckInputError as exc:
        if args.format == "json":
            print(json.dumps({"tool": "php2shell-http-check", "error": str(exc)}, sort_keys=True))
        else:
            print("Input error: " + str(exc), file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, sort_keys=True))
    else:
        print(_human_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Application hostname safeguard and loopback-only TLS regression checks."""

import socket
import ssl
import sys
import time
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8443
CA_FILE = Path(__file__).resolve().parent / "certs" / "ca.crt"
EXPECTED_RESPONSE = b"TLS connection successful!"
TIMEOUT = 5


def secure_wrap_bio(context, incoming, outgoing, server_hostname=None):
    """Reject unsafe inputs/settings; never silently weaken verification."""
    if not isinstance(server_hostname, str) or not server_hostname.strip():
        raise ValueError("A non-empty server_hostname is required")
    if not context.check_hostname:
        raise ValueError("Hostname verification must be enabled")
    if context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("Certificate verification must be CERT_REQUIRED")
    return context.wrap_bio(
        incoming, outgoing, server_side=False, server_hostname=server_hostname
    )


def client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class ResponseError(Exception):
    """The authenticated peer did not send the expected lab response."""


def exchange(context, hostname):
    """Pump MemoryBIO records with one deadline for handshake and response."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = secure_wrap_bio(context, incoming, outgoing, hostname)
    deadline = time.monotonic() + TIMEOUT
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as sock:
        def set_timeout():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TLS exchange deadline exceeded")
            sock.settimeout(remaining)

        def flush():
            while outgoing.pending:
                set_timeout()
                sock.sendall(outgoing.read())

        def receive():
            set_timeout()
            data = sock.recv(16384)
            if not data:
                raise ConnectionError("Server closed before the expected response completed")
            incoming.write(data)

        def perform(operation):
            while True:
                set_timeout()
                try:
                    result = operation()
                except ssl.SSLWantReadError:
                    flush()
                    receive()
                except ssl.SSLWantWriteError:
                    if not outgoing.pending:
                        raise RuntimeError("TLS requested a write without pending output")
                    flush()
                else:
                    # Includes the final client handshake flight, even when
                    # do_handshake() has already returned successfully.
                    flush()
                    return result

        perform(tls.do_handshake)
        response = bytearray()
        while len(response) < len(EXPECTED_RESPONSE):
            data = perform(lambda: tls.read(16384))
            if not data:
                raise ResponseError("TLS closed before the complete lab response")
            response.extend(data)
            if not EXPECTED_RESPONSE.startswith(response):
                raise ResponseError(f"Unexpected server response: {bytes(response)!r}")
        if bytes(response) != EXPECTED_RESPONSE:
            raise ResponseError(f"Unexpected server response: {bytes(response)!r}")
        return f"TLS={tls.version()}; cipher={tls.cipher()[0]}; response={bytes(response)!r}"


def test_connection(hostname, expected, trust_lab_ca=True):
    try:
        context = client_context()
        if trust_lab_ca:
            context.load_verify_locations(cafile=str(CA_FILE))
        # Without loading any trust anchors, the CA-signed lab certificate must
        # fail chain verification even though its hostname matches.
        detail = exchange(context, hostname)
        actual = "SUCCESS"
    except ssl.SSLCertVerificationError as error:
        # OpenSSL X509_V_ERR_HOSTNAME_MISMATCH. Other verification failures
        # must never pass the hostname-mismatch assertion.
        actual = "HOSTNAME_MISMATCH" if error.verify_code == 62 else "CERTIFICATE_FAILURE"
        detail = f"{type(error).__name__}: code={error.verify_code}; {error.verify_message}"
    except ResponseError as error:
        actual, detail = "RESPONSE_FAILURE", str(error)
    except (OSError, ssl.SSLError) as error:
        actual, detail = "INFRASTRUCTURE_ERROR", f"{type(error).__name__}: {error}"
    except Exception as error:
        actual, detail = "UNEXPECTED_ERROR", f"{type(error).__name__}: {error}"
    passed = actual == expected
    print(f"{'PASS' if passed else 'FAIL'}: hostname={hostname!r}, trust_lab_ca={trust_lab_ca}: "
          f"expected={expected}; actual={actual}")
    print("  " + detail)
    return passed


def test_guard():
    cases = [
        ("omitted hostname", {}, "hostname"),
        ("None", {"server_hostname": None}, "hostname"),
        ("empty", {"server_hostname": ""}, "hostname"),
        ("whitespace", {"server_hostname": " \t\n"}, "hostname"),
        ("integer", {"server_hostname": 123}, "hostname"),
        ("bytes", {"server_hostname": b"localhost"}, "hostname"),
        ("hostname checking disabled", {"server_hostname": "localhost"}, "checking"),
        ("CERT_OPTIONAL", {"server_hostname": "localhost"}, "certificates"),
    ]
    messages = {
        "hostname": "A non-empty server_hostname is required",
        "checking": "Hostname verification must be enabled",
        "certificates": "Certificate verification must be CERT_REQUIRED",
    }
    passed_count = 0
    for label, kwargs, kind in cases:
        context = client_context()
        if kind == "checking":
            context.check_hostname = False
        elif kind == "certificates":
            context.verify_mode = ssl.CERT_OPTIONAL
        try:
            secure_wrap_bio(context, ssl.MemoryBIO(), ssl.MemoryBIO(), **kwargs)
        except Exception as error:
            passed = type(error) is ValueError and str(error) == messages[kind]
            detail = f"{type(error).__name__}: {error}"
        else:
            passed, detail = False, "unsafe input/settings accepted"
        print(f"{'PASS' if passed else 'FAIL'}: guard {label}: {detail}")
        passed_count += passed
    return passed_count, len(cases)


def main():
    print("Python executable:", sys.executable)
    print("Python version:", sys.version.replace("\n", " "))
    print("OpenSSL:", ssl.OPENSSL_VERSION)
    print(f"Endpoint: {HOST}:{PORT}; check_hostname=True; verify_mode=CERT_REQUIRED")
    print("CA:", CA_FILE)
    print("Application guard tests (no network):")
    passed, total = test_guard()
    print(f"Guard summary: {passed}/{total} PASS")
    if not CA_FILE.is_file():
        print("FAIL: integration prerequisite: lab CA certificate is missing")
        print("NOT RUN: hostname mismatch, trusted response, untrusted certificate tests")
        return 1
    print("Local TLS integration tests:")
    for hostname, expected, trust in (
        ("localhost", "HOSTNAME_MISMATCH", True),
        ("attacker.test", "SUCCESS", True),
        ("attacker.test", "CERTIFICATE_FAILURE", False),
    ):
        passed += test_connection(hostname, expected, trust)
        total += 1
    print(f"Summary: {passed}/{total} PASS; {total - passed} FAIL")
    print("attacker.test is a matching-identity control, not a substitute for the intended hostname.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

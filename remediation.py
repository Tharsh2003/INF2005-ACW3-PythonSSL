
"""Application-level mitigation with full TLS handshake verification."""

import socket
import ssl
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8443
CA_FILE = Path(__file__).resolve().parent / "certs" / "ca.crt"


def secure_wrap_bio(context, incoming, outgoing, server_hostname):

    # Reject missing or empty hostnames
    if not isinstance(server_hostname, str) or not server_hostname.strip():
        raise ValueError("A non-empty server_hostname is required")

    # Ensure hostname verification is enabled
    if not context.check_hostname:
        raise ValueError("Hostname verification must be enabled")

    return context.wrap_bio(
        incoming,
        outgoing,
        server_side=False,
        server_hostname=server_hostname
    )


def test_connection(server_hostname):

    print("Testing hostname:", repr(server_hostname))

    context = ssl.create_default_context(cafile=str(CA_FILE))
    context.check_hostname = True

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()

    try:
        tls_object = secure_wrap_bio(
            context,
            incoming,
            outgoing,
            server_hostname
        )

    except ValueError as error:
        print("Application validation: REJECTED")
        print("Reason:", error)
        print("-" * 50)
        return

    print("Application validation: PASSED")

    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            sock.settimeout(5)

            while True:
                try:
                    tls_object.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    pass

                while outgoing.pending:
                    sock.sendall(outgoing.read())

                data = sock.recv(16384)

                if not data:
                    raise ConnectionError(
                        "Server closed connection during handshake"
                    )

                incoming.write(data)

            print("TLS handshake: SUCCESS")

    except ssl.SSLCertVerificationError as error:
        print("TLS handshake: REJECTED")
        print("Reason:", error)

    except (ssl.SSLError, OSError) as error:
        print("TLS connection: FAILED")
        print("Reason:", type(error).__name__, str(error))

    print("-" * 50)


if __name__ == "__main__":

    print("CVE-2026-19553 - Full Remediation Test")
    print()

    for hostname in (None, "", "localhost", "attacker.test"):
        test_connection(hostname)

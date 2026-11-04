
"""Application-level mitigation for CVE-2026-19553."""

import ssl
from pathlib import Path

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


if __name__ == "__main__":

    context = ssl.create_default_context(cafile=str(CA_FILE))
    context.check_hostname = True

    print("Application-level remediation test")
    print("Hostname verification:", context.check_hostname)
    print()

    for hostname in (None, "", "localhost"):

        try:
            secure_wrap_bio(
                context,
                ssl.MemoryBIO(),
                ssl.MemoryBIO(),
                hostname
            )

            print(
                repr(hostname),
                "-> accepted for TLS setup (handshake not performed)"
            )

        except ValueError as error:
            print(repr(hostname), "-> rejected:", error)

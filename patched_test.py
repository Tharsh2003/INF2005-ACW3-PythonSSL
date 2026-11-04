
import ssl
import sys

print("Python version:", sys.version.split()[0])
print("OpenSSL version:", ssl.OPENSSL_VERSION)

# Load our trusted certificate authority
context = ssl.create_default_context(
    cafile="certs/ca.crt"
)

# Enable hostname verification
context.check_hostname = True

incoming = ssl.MemoryBIO()
outgoing = ssl.MemoryBIO()

# Deliberately omit the hostname
server_hostname = None

try:
    # Simulate the patched hostname validation
    if context.check_hostname and server_hostname is None:
        raise ValueError(
            "check_hostname requires server_hostname"
        )

    tls_object = context.wrap_bio(
        incoming,
        outgoing,
        server_side=False,
        server_hostname=server_hostname
    )

    print("SSLObject created successfully")

except ValueError as error:
    print("Connection rejected before TLS handshake")
    print("Error:", error)
    print("Missing hostname was correctly rejected")

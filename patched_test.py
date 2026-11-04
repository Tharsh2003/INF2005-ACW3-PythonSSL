"""Test the actual CPython SSLContext.wrap_bio() behavior."""

import ssl
import sys
from pathlib import Path

CA_FILE = Path(__file__).resolve().parent / "certs" / "ca.crt"

print("Python version:", sys.version.split()[0])
print("OpenSSL version:", ssl.OPENSSL_VERSION)

context = ssl.create_default_context(cafile=str(CA_FILE))
context.check_hostname = True

try:
    context.wrap_bio(
        ssl.MemoryBIO(),
        ssl.MemoryBIO(),
        server_side=False,
        server_hostname=None
    )

except ValueError as error:
    print("RESULT: Actual runtime rejected missing hostname")
    print("Error:", error)

else:
    print("RESULT: Actual runtime accepted missing hostname")
    print("WARNING: No built-in rejection observed")
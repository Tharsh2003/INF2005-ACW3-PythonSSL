# CVE-2026-19553 — Python TLS Hostname Verification Vulnerability

## 1. Project Overview

This project demonstrates a TLS hostname verification issue involving Python's `SSLContext.wrap_bio()` method.

The objective is to investigate how a TLS connection can be established without verifying the server's hostname, even when hostname checking is enabled.

The project includes a locally hosted TLS server, a certificate authority, an exploitation script, and a simulated remediation test.

## 2. Vulnerability Description

CVE-2026-19553 concerns hostname verification when using Python's `SSLContext.wrap_bio()` method.

When `server_hostname=None` is supplied, the tested Python implementation allows the TLS handshake to succeed without checking the server's identity against an expected hostname, despite `check_hostname=True`.

This creates a security risk because a client may accept a certificate from a trusted certificate authority without confirming that it belongs to the intended server.

## 3. Testing Environment

- Operating system: Windows
- Development environment: Visual Studio Code
- Python version: 3.14.7
- OpenSSL version: 3.5.7
- TLS server address: 127.0.0.1
- TLS server port: 8443
- Server certificate hostname: attacker.test
- Certificate generation library: cryptography

## 4. Project Files

- `generate_certs.py` — Generates the test certificate authority and server certificates
- `tls_server.py` — Starts the local TLS server
- `exploit.py` — Tests TLS connections using `SSLContext.wrap_bio()`
- `patched_test.py` — Simulates an application-level hostname validation safeguard
- `certs/` — Stores generated certificates and private keys
- `screenshots/` — Stores evidence of the test results

## 5. Exploitation Results

**Test 1 — Missing hostname**

The client connected with `server_hostname=None` while `check_hostname=True`.

Result: TLS handshake successful. Hostname verification was not enforced.

**Test 2 — Incorrect hostname**

The client connected with `server_hostname="localhost"`, while the server certificate identified `attacker.test`.

Result: TLS connection rejected due to a hostname mismatch.

**Test 3 — Remediation simulation**

An explicit validation check was added to reject a missing hostname before creating the TLS object.

Result: Connection rejected before the TLS handshake.

This third test demonstrates an application-level safeguard rather than the official CPython patch.

## 6. Security Impact

TLS hostname verification helps ensure that a client is communicating with its intended server.

If hostname verification is skipped, a client may establish a TLS connection with an unintended server whose certificate is trusted by the client.

Depending on the surrounding application and trust configuration, this could enable server impersonation or man-in-the-middle attacks.

## 7. Conclusion

The local testing demonstrated that omitting `server_hostname` allowed a TLS handshake to succeed without hostname verification.

When an incorrect hostname was explicitly supplied, Python correctly rejected the certificate.

The remediation simulation demonstrated how an application can prevent the missing-hostname case by validating the hostname before establishing the TLS connection.

Testing against an officially patched CPython version remains necessary to demonstrate the actual upstream fix.
# CVE-2026-19553 — Python TLS Hostname Verification Vulnerability

## 1. Project Overview

This project demonstrates CVE-2026-19553, a TLS hostname verification vulnerability affecting Python's `SSLContext.wrap_bio()` method.

The objective is to investigate how a TLS handshake can succeed without verifying the server's hostname, even when hostname checking is enabled.

The project includes a locally hosted TLS server, a test certificate authority, an exploitation script, an application-level remediation, and a comparison between vulnerable and patched Python versions.

All exploitation testing is performed locally using `127.0.0.1`. No external servers or production systems are targeted.

## 2. Vulnerability Description

CVE-2026-19553 concerns improper hostname verification when using Python's `SSLContext.wrap_bio()` method.

In vulnerable Python versions, supplying `server_hostname=None` can allow a TLS handshake to succeed without checking the server's certificate against an expected hostname, despite `check_hostname=True`.

This occurs because the TLS connection is created without an expected hostname for certificate matching.

Although certificate-chain verification may still be performed, the absence of hostname verification means that a certificate issued by a trusted certificate authority could be accepted without confirming that it belongs to the intended server.

This could potentially allow server impersonation or man-in-the-middle attacks, depending on the application's trust configuration and network environment.

**CVE details:**

- CVE ID: CVE-2026-19553
- Affected component: Python / CPython `SSLContext.wrap_bio()`
- Severity: High
- CVSS score: 7.6
- Vulnerable version tested: Python 3.14.7
- Patched version tested: Python 3.14.10

## 3. Testing Environment

The experiment was conducted using the following environment:

- Operating system: Windows
- Development environment: Visual Studio Code
- Vulnerable Python version: 3.14.7
- Vulnerable OpenSSL version: 3.5.7
- Patched Python version: 3.14.10
- Patched OpenSSL version: 3.5.9
- TLS server address: 127.0.0.1
- TLS server port: 8443
- Server certificate hostname: attacker.test
- Certificate generation library: cryptography

A local certificate authority (CA) was generated to sign the test server certificate.

The TLS client was configured to trust this CA so that the experiment could focus specifically on hostname verification rather than certificate-chain trust failures.

## 4. Project Files

| File | Description |
|---|---|
| `generate_certs.py` | Generates the local certificate authority and TLS server certificate |
| `tls_server.py` | Starts the locally hosted TLS server |
| `exploit.py` | Tests TLS connections using `SSLContext.wrap_bio()` |
| `patched_test.py` | Tests actual CPython behavior on vulnerable and patched Python versions |
| `remediation.py` | Implements an application-level safeguard against missing or empty hostnames |
| `requirements.txt` | Lists the required Python dependency |
| `certs/` | Stores locally generated certificates and private keys |
| `screenshots/` | Stores evidence of the exploitation and remediation results |
| `.gitignore` | Excludes generated certificates, private keys and temporary files from Git tracking |

## 5. Exploitation Results

### Test 1 — Missing Hostname

The client was configured with:

```python
context.check_hostname = True
server_hostname = None
```

The TLS server presented a certificate issued for `attacker.test`.

**Observed output:**

```text
Python: 3.14.7
OpenSSL: OpenSSL 3.5.7 9 Jun 2026
server_hostname: None
check_hostname: True
verify_mode: 2
RESULT: TLS handshake successful
WARNING: Missing hostname was accepted
```

**Result:** Successful exploitation of the missing-hostname verification issue.

Although hostname verification was enabled, the TLS handshake completed without checking the server certificate against an expected hostname.

### Test 2 — Incorrect Hostname

The client was configured with:

```python
server_hostname = "localhost"
```

However, the TLS server certificate was issued for `attacker.test`.

**Observed output:**

```text
RESULT: TLS connection rejected
Error: SSLCertVerificationError
certificate verify failed: Hostname mismatch,
certificate is not valid for 'localhost'.
```

**Result:** TLS connection rejected due to a hostname mismatch.

This demonstrates that hostname verification is enforced when an expected hostname is explicitly provided.

### Test 3 — Vulnerable Versus Patched Python

The same `SSLContext.wrap_bio()` configuration was tested on two Python versions using:

```python
context.check_hostname = True
server_hostname = None
```

**Python 3.14.7 — Vulnerable runtime**

```text
Python version: 3.14.7
RESULT: Actual runtime accepted missing hostname
WARNING: No built-in rejection observed
```

**Python 3.14.10 — Patched runtime**

```text
Python version: 3.14.10
RESULT: Actual runtime rejected missing hostname
Error: check_hostname requires server_hostname
```

**Result:** The vulnerable runtime accepted the missing hostname, while the patched runtime rejected it.

This comparison tests TLS object creation rather than performing a complete network handshake.

### Test 4 — Application-Level Remediation

An additional safeguard was implemented in `remediation.py`.

The function checks that a non-empty hostname is supplied and that hostname verification is enabled before calling `SSLContext.wrap_bio()`.

**Observed output:**

```text
Application-level remediation test
Hostname verification: True

None -> rejected: A non-empty server_hostname is required
'' -> rejected: A non-empty server_hostname is required
'localhost' -> accepted for TLS setup (handshake not performed)
```

**Result:** Missing and empty hostnames were rejected before TLS setup.

The `localhost` input was accepted for TLS object creation because it was a non-empty hostname. Its certificate would still need to be verified during the TLS handshake.

This application-level mitigation is separate from the official CPython patch.

## 6. Security Impact

TLS hostname verification is an important security mechanism that ensures a client is communicating with its intended server.

When hostname verification is skipped, a TLS client may accept a certificate that chains to a trusted CA without checking whether it identifies the expected server.

Potential security consequences include:

- Server impersonation
- Man-in-the-middle attacks under suitable attacker and trust conditions
- Connections to unintended TLS servers
- Exposure of sensitive information if an application sends data over an incorrectly authenticated connection

The impact depends on the application's TLS configuration, trusted certificate authorities and surrounding network environment.

## 7. Steps to Reproduce the Vulnerability

### Step 1 — Install Dependencies

Open the project folder in Visual Studio Code.

In the PowerShell terminal, run:

```powershell
py -m pip install -r requirements.txt
```

The dependency is specified in `requirements.txt`:

```text
cryptography>=43,<47
```

### Step 2 — Generate TLS Certificates

Run:

```powershell
py .\generate_certs.py
```

This generates a local certificate authority and a TLS server certificate for `attacker.test`.

The certificates and private keys are stored in the `certs/` directory.

These files are excluded from Git tracking and should be generated locally on each computer.

### Step 3 — Start the TLS Server

Open Terminal 1 and run:

```powershell
py .\tls_server.py
```

The server listens on:

```text
127.0.0.1:8443
```

Leave the server running during the following exploitation tests.

### Step 4 — Test the Missing Hostname

Open Terminal 2 and run:

```powershell
py .\exploit.py --hostname missing
```

**Observed result:**

```text
RESULT: TLS handshake successful
WARNING: Missing hostname was accepted
```

This demonstrates that Python 3.14.7 allows the TLS handshake to complete without hostname verification.

### Step 5 — Test an Incorrect Hostname

Run:

```powershell
py .\exploit.py --hostname localhost
```

**Observed result:**

```text
RESULT: TLS connection rejected
Error: SSLCertVerificationError
```

The certificate is rejected because it identifies `attacker.test` rather than `localhost`.

### Step 6 — Test the Correct Hostname

Run:

```powershell
py .\exploit.py --hostname attacker.test
```

**Observed result:**

```text
RESULT: TLS handshake successful
Hostname supplied; certificate verified against it
```

This demonstrates that the TLS handshake succeeds when the expected hostname matches the certificate.

### Step 7 — Compare Vulnerable and Patched Python Versions

Run the runtime validation test using vulnerable Python 3.14.7:

```powershell
& "C:\Users\thars\AppData\Local\Programs\Python\Python314\python.exe" .\patched_test.py
```

**Observed result:**

```text
RESULT: Actual runtime accepted missing hostname
WARNING: No built-in rejection observed
```

Next, run the same test using patched Python 3.14.10:

```powershell
& "C:\Users\thars\Python3148-Patched\python.exe" .\patched_test.py
```

**Observed result:**

```text
RESULT: Actual runtime rejected missing hostname
Error: check_hostname requires server_hostname
```

The Python executable paths shown above are specific to the original testing environment. They may differ on other computers.

### Step 8 — Run the Application-Level Remediation

Run:

```powershell
py .\remediation.py
```

**Observed result:**

```text
Application-level remediation test
Hostname verification: True

None -> rejected: A non-empty server_hostname is required
'' -> rejected: A non-empty server_hostname is required
'localhost' -> accepted for TLS setup (handshake not performed)
```

This demonstrates that application-level validation can prevent the missing-hostname configuration before TLS setup.

## 8. Screenshot Evidence

The following screenshots were captured during testing:

| Screenshot | Description |
|---|---|
| `screenshots/01_hostname_bypass.png` | Successful TLS handshake without hostname verification |
| `screenshots/02_hostname_mismatch.png` | TLS connection rejected due to hostname mismatch |
| `screenshots/03_remediation_test.png` | Missing and empty hostnames rejected by application-level validation |
| `screenshots/04_vulnerable_vs_patched.png` | Comparison between vulnerable Python 3.14.7 and patched Python 3.14.10 |

These screenshots provide supporting evidence for the vulnerability assessment, exploitation and remediation results.

## 9. Remediation and Recommended Defences

### 9.1 Upgrade Python

The recommended remediation is to use a patched CPython release that enforces hostname requirements when hostname verification is enabled.

In this project, Python 3.14.10 was tested and rejected `server_hostname=None`.

### 9.2 Validate the Expected Hostname

Applications using `SSLContext.wrap_bio()` should explicitly require a valid, non-empty hostname.

The `remediation.py` script demonstrates this approach by rejecting missing and empty hostname values before TLS object creation.

### 9.3 Maintain Certificate Verification

Applications should maintain certificate verification and hostname checking using:

```python
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
```

Both certificate-chain validation and hostname matching are important for authenticating the intended TLS server.

## 10. Limitations

The experiment was performed using a locally hosted TLS server and locally generated certificates.

The client was explicitly configured to trust the test certificate authority. This allowed hostname verification to be investigated separately from certificate-chain validation.

The patched-runtime comparison demonstrated rejection of the missing hostname during TLS object creation. It did not independently perform a full network handshake on Python 3.14.10.

The application-level remediation was implemented separately from the official CPython patch.

The experiment did not involve interception of real network traffic, an external attacker or a production system.

The results demonstrate the vulnerability under the tested conditions and do not establish that every application using Python TLS is exploitable.

## 11. Conclusion

The experiment demonstrated CVE-2026-19553 using Python 3.14.7 and a locally hosted TLS server.

When `server_hostname=None` was supplied with `check_hostname=True`, the TLS handshake completed successfully without verifying the server certificate against an expected hostname.

When `localhost` was explicitly supplied, Python rejected the connection because the certificate identified `attacker.test`.

The same missing-hostname configuration was then tested on Python 3.14.10, which rejected the unsafe TLS setup with a `ValueError`.

An additional application-level mitigation successfully rejected missing and empty hostnames before TLS object creation.

Together, these results demonstrate the vulnerable behavior, a hostname verification control test, patched-runtime behavior and an application-level safeguard.

## 12. References

1. CVE Program. **CVE-2026-19553 — Official CVE Record.**  
   https://www.cve.org/CVERecord?id=CVE-2026-19553

2. National Institute of Standards and Technology. **National Vulnerability Database — CVE-2026-19553.**  
   https://nvd.nist.gov/vuln/detail/CVE-2026-19553

3. Python Software Foundation. **Python Security Announcement.**  
   https://mail.python.org/archives/list/security-announce@python.org/thread/QNZRG3YOAMTHDCMVCICXGY6YEFPY2VDL/

4. Python Software Foundation. **CPython Security Fix — Pull Request #158503.**  
   https://github.com/python/cpython/pull/158503

5. Python Software Foundation. **Python SSL Module Documentation.**  
   https://docs.python.org/3/library/ssl.html
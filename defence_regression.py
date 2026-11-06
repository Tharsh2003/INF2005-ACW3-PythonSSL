"""Run the Defence regression suite in a disposable, loopback-only lab."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent


def run(command, cwd, timeout=40):
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as error:
        elapsed = time.monotonic() - started
        print(f"TIMEOUT after {elapsed:.2f}s (limit {timeout}s): {command}",
              file=sys.stderr, flush=True)
        for label, output in (("stdout", error.stdout), ("stderr", error.stderr)):
            # TimeoutExpired may contain bytes even when text=True.
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            print(f"Captured {label}:\n{output or '(empty)'}",
                  file=sys.stderr, flush=True)
        raise
    print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    if result.returncode:
        raise RuntimeError(f"Command exited {result.returncode}: {command}")


def verify_certificates(lab):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca = x509.load_pem_x509_certificate((lab / "certs/ca.crt").read_bytes())
    server = x509.load_pem_x509_certificate((lab / "certs/server.crt").read_bytes())
    ca.verify_directly_issued_by(ca)
    server.verify_directly_issued_by(ca)
    now = datetime.now(timezone.utc)
    checks = [
        ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
        ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign,
        not server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
        server.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        .value.get_values_for_type(x509.DNSName) == ["attacker.test"],
        ExtendedKeyUsageOID.SERVER_AUTH in server.extensions
        .get_extension_for_class(x509.ExtendedKeyUsage).value,
    ]
    for name, cert in (("ca", ca), ("server", server)):
        checks.append(cert.not_valid_before_utc <= now <= cert.not_valid_after_utc)
        key = serialization.load_pem_private_key(
            (lab / f"certs/{name}.key").read_bytes(), password=None
        )
        checks.append(key.public_key().public_numbers() == cert.public_key().public_numbers())
    if not all(checks):
        raise RuntimeError("Certificate constraints, validity, SAN, EKU or key pairing failed")
    print("PASS: fresh certificate signatures, constraints, validity, SAN and key pairing", flush=True)


@contextmanager
def local_server(interpreter, lab):
    # Retain startup stderr separately; this fixed-size suite emits little stdout.
    with tempfile.TemporaryFile(mode="w+t") as log:
        process = subprocess.Popen(
            [interpreter, "-B", "-u", "tls_server.py"], cwd=lab,
            stdout=subprocess.PIPE, stderr=log, text=True,
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=10):
                    raise RuntimeError("Local TLS server startup timed out")
                first_line = process.stdout.readline().strip()
            if first_line != "TLS server running on 127.0.0.1:8443":
                raise RuntimeError(f"Local TLS server failed to start: {first_line!r}")
            print("PASS: local TLS server ready on 127.0.0.1:8443", flush=True)
            yield
            if process.poll() is not None:
                raise RuntimeError("TLS server exited unexpectedly during tests")
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate(timeout=5)
            log.seek(0)
            print("Server diagnostics (EOF errors can accompany rejected clients):", flush=True)
            print(output + log.read(), flush=True)
            print("Server stopped; exit code:", process.returncode, flush=True)


# Reserve a loopback port without listening: connections fail or time out, and
# another process cannot take the port during these checks. No source changes.
INFRASTRUCTURE_TEST = '''
import contextlib
import io
import socket
import remediation as r

with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    r.PORT = reservation.getsockname()[1]
    r.TIMEOUT = 0.5
    for expected in ("INFRASTRUCTURE_ERROR", "HOSTNAME_MISMATCH", "CERTIFICATE_FAILURE", "SUCCESS"):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = r.test_connection("localhost", expected)
        detail = output.getvalue()
        correct = result == (expected == "INFRASTRUCTURE_ERROR")
        correct = correct and "actual=INFRASTRUCTURE_ERROR" in detail and any(name in detail for name in ("ConnectionRefusedError", "TimeoutError"))
        print(f"{'PASS' if correct else 'FAIL'}: unavailable server vs expected {expected}")
        print("  " + detail.splitlines()[-1].strip())
        if not correct:
            print(detail)
            raise SystemExit(1)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable", default="/usr/local/bin/python3.12")
    parser.add_argument("--patched", default=str(Path.home() / ".pyenv/versions/3.12.15/bin/python3"))
    args = parser.parse_args()
    interpreters = [str(Path(p).expanduser().absolute()) for p in (args.vulnerable, args.patched)]
    try:
        for interpreter, version in zip(interpreters, ("3.12.6", "3.12.15")):
            run([interpreter, "-I", "-B", "-c",
                 "import sys; v='.'.join(map(str,sys.version_info[:3])); "
                 "print(sys.executable, v); "
                 f"sys.exit(0 if v == {version!r} and sys.implementation.name == 'cpython' else 1)"], ROOT)
        # Copies are byte-for-byte fixtures: the existing generator's __file__
        # and the server's relative certificate paths resolve inside this lab.
        with tempfile.TemporaryDirectory(prefix="acw3-defence-") as directory:
            lab = Path(directory)
            for name in ("generate_certs.py", "tls_server.py", "remediation.py", "patched_test.py"):
                shutil.copyfile(ROOT / name, lab / name)
            run([sys.executable, "-B", "-u", "generate_certs.py"], lab, timeout=120)
            verify_certificates(lab)
            failed = False
            with local_server(interpreters[1], lab):
                for interpreter in interpreters:
                    for script in ("patched_test.py", "remediation.py"):
                        print(f"\nRunning {script}: {interpreter}", flush=True)
                        try:
                            run([interpreter, "-B", script], lab)
                        except (RuntimeError, subprocess.TimeoutExpired) as error:
                            print("FAIL:", error, flush=True)
                            failed = True
            for interpreter in interpreters:
                print(f"\nInfrastructure regression: {interpreter}", flush=True)
                try:
                    run([interpreter, "-B", "-c", INFRASTRUCTURE_TEST], lab)
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    print("FAIL:", error, flush=True)
                    failed = True
            if failed:
                raise RuntimeError("One or more Defence regression groups failed")
        print("PASS: all Defence regression groups; temporary lab cleaned up")
        return 0
    except (OSError, ValueError, ImportError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

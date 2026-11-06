"""Offline wrap_bio constructor checks for the project's CPython 3.12 pair.

No sockets, certificates, or TLS handshakes are used. Successful construction
is not certificate verification. Warning promotion is an additional policy,
not the default protection supplied by Python 3.12.15.
"""

import argparse
import re
import ssl
import sys
import warnings


HOSTNAME_WARNING = "check_hostname requires server_hostname"


def run_mode(mode, emits_warning):
    """Check constructor outcomes and warnings under one temporary policy."""
    title = (
        "Default runtime behavior (warnings recorded, not promoted)"
        if mode == "default"
        else "Additional warning-as-error mitigation (explicit application policy)"
    )
    print(f"\n{title}")
    cases = (
        ("omitted server_hostname", {}, True),
        ("explicit None", {"server_hostname": None}, True),
        ("empty string", {"server_hostname": ""}, False),
        ("valid hostname", {"server_hostname": "localhost"}, False),
    )
    failures = 0
    for label, kwargs, missing in cases:
        expected_exception = None
        expected_warnings = []
        if missing and emits_warning:
            if mode == "warning-as-error":
                expected_exception = DeprecationWarning
            else:
                expected_warnings = [(DeprecationWarning, HOSTNAME_WARNING)]
        elif label == "empty string":
            expected_exception = ValueError

        # Context setup errors must not count as expected wrap_bio rejections.
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        except Exception as error:
            print(f"FAIL: {label}: context setup: {type(error).__name__}: {error}")
            failures += 1
            continue

        error = None
        with warnings.catch_warnings(record=True) as recorded:
            # Observe every warning, including unexpected ones. This does not
            # change whether the constructor raises or returns normally.
            warnings.simplefilter("always")
            if mode == "warning-as-error":
                # Anchor the exact message and limit promotion to this category.
                # The catch_warnings scope restores all filters after this call.
                warnings.filterwarnings(
                    "error",
                    message=r"\A" + re.escape(HOSTNAME_WARNING) + r"\Z",
                    category=DeprecationWarning,
                )
            try:
                context.wrap_bio(
                    ssl.MemoryBIO(), ssl.MemoryBIO(), server_side=False, **kwargs
                )
            except Exception as exc:
                error = exc

        actual_warnings = [(item.category, str(item.message)) for item in recorded]
        exception_matches = (
            error is None if expected_exception is None
            else type(error) is expected_exception
        )
        if expected_exception is DeprecationWarning:
            exception_matches = exception_matches and str(error) == HOSTNAME_WARNING
        passed = exception_matches and actual_warnings == expected_warnings
        expected = expected_exception.__name__ if expected_exception else "ACCEPTED"
        actual = type(error).__name__ if error is not None else "ACCEPTED"
        print(f"{'PASS' if passed else 'FAIL'}: {label}: expected={expected}; actual={actual}")
        print("  Expected warnings:", [(c.__name__, m) for c, m in expected_warnings])
        print("  Actual warnings:", [(c.__name__, m) for c, m in actual_warnings])
        if error is not None:
            print(f"  Exception: {type(error).__name__}: {error}")
        failures += not passed

    print(f"Mode summary: {len(cases) - failures}/{len(cases)} PASS; {failures} FAIL")
    if mode == "warning-as-error" and not emits_warning:
        print("Baseline limitation: no warning is emitted, so this policy cannot block missing hostnames.")
    return failures, len(cases)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("default", "warning-as-error", "all"), default="all",
        help="Constructor test policy (default: run both modes)",
    )
    args = parser.parse_args(argv)
    print("Python version:", sys.version.replace("\n", " "))
    print("Executable:", sys.executable)
    print("OpenSSL version:", ssl.OPENSSL_VERSION)
    print("Scope: TLS object construction only; no network or certificate verification")
    print("check_hostname: True; verify_mode: CERT_REQUIRED")

    # Branch-specific expectations, not runtime patch detection.
    profiles = {
        (3, 12, 6): ("vulnerable baseline", False),
        (3, 12, 15): ("3.12 security backport: warning by default", True),
    }
    version = tuple(sys.version_info[:3])
    if sys.implementation.name != "cpython" or version not in profiles:
        print("FAIL: Unsupported interpreter; expected CPython 3.12.6 or 3.12.15")
        return 2
    profile, emits_warning = profiles[version]
    print("Expected profile:", profile)
    modes = ("default", "warning-as-error") if args.mode == "all" else (args.mode,)
    failures = total = 0
    for mode in modes:
        mode_failures, count = run_mode(mode, emits_warning)
        failures += mode_failures
        total += count
    print(f"\nSummary: {total - failures}/{total} PASS; {failures} FAIL")
    print("PASS means the observed behavior matches expectations, not that every connection is safe.")
    print("ACCEPTED means SSLObject created, not a verified TLS connection.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

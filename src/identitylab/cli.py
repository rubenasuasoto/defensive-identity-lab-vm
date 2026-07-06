from __future__ import annotations

import argparse
import sys

from identitylab.site import build_site
from identitylab.verify import checks_passed, verify_urls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="identitylab",
        description="Build and verify the defensive identity lab hub.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("build-site", help="Generate site/index.html.")
    subparsers.add_parser("verify", help="Verify configured public lab URLs.")
    subparsers.add_parser("all", help="Build the site and verify configured URLs.")
    args = parser.parse_args(argv)

    if args.command == "build-site":
        output = build_site()
        print(f"Built {output}")
        return 0

    if args.command == "verify":
        return _run_verify()

    if args.command == "all":
        output = build_site()
        print(f"Built {output}")
        return _run_verify()

    parser.error(f"Unknown command: {args.command}")
    return 2


def _run_verify() -> int:
    checks = verify_urls()
    for check in checks:
        status = check.status_code if check.status_code is not None else "ERR"
        marker = "OK" if check.ok else "FAIL"
        print(f"{marker:4} {status} {check.label}: {check.url}")
    return 0 if checks_passed(checks) else 1


if __name__ == "__main__":
    sys.exit(main())

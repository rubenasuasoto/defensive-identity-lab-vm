from __future__ import annotations

import argparse
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from identitylab.paths import SITE_DIR
from identitylab.site import build_site
from identitylab.verify import checks_passed, verify_urls
from identitylab.vm import (
    build_readiness_report,
    format_readiness_markdown,
    report_passed,
    write_evidence,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="identitylab",
        description="Build and verify the defensive identity lab hub.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("build-site", help="Generate site/index.html.")
    subparsers.add_parser("verify", help="Verify configured public lab URLs.")
    subparsers.add_parser("all", help="Build the site and verify configured URLs.")
    subparsers.add_parser("vm-check", help="Check local VM/workstation readiness.")
    evidence_parser = subparsers.add_parser(
        "vm-evidence",
        help="Write local VM readiness evidence.",
    )
    evidence_parser.add_argument(
        "--output-dir",
        default="evidence/latest",
        help="Directory for readiness evidence files.",
    )
    serve_parser = subparsers.add_parser("serve", help="Serve the static hub locally.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8088)
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

    if args.command == "vm-check":
        report = build_readiness_report()
        print(format_readiness_markdown(report))
        return 0 if report_passed(report) else 1

    if args.command == "vm-evidence":
        json_path, md_path = write_evidence(Path(args.output_dir))
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
        return 0

    if args.command == "serve":
        output = build_site()
        print(f"Built {output}")
        return _serve(args.host, args.port)

    parser.error(f"Unknown command: {args.command}")
    return 2


def _run_verify() -> int:
    checks = verify_urls()
    for check in checks:
        status = check.status_code if check.status_code is not None else "ERR"
        marker = "OK" if check.ok else "FAIL"
        print(f"{marker:4} {status} {check.label}: {check.url}")
    return 0 if checks_passed(checks) else 1


def _serve(host: str, port: int) -> int:
    handler = lambda *args, **kwargs: SimpleHTTPRequestHandler(  # noqa: E731
        *args,
        directory=str(SITE_DIR),
        **kwargs,
    )
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Serving http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

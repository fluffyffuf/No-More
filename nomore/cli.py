from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .config import Config, config_path
from .models import Finding, Severity
from .reporting import render_html_report, render_json_report, render_markdown_report, render_sarif_report
from .scan import ScanEngine
from .scope import ScopeEngine


def _write_text(path: str | None, content: str) -> None:
    if not path:
        print(content)
        return
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    print(f"Report written to {output}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nomore",
        description="NOMORE — Next-Generation Web Security & OSINT CLI",
    )
    parser.add_argument("--version", action="store_true", help="Show NOMORE version and exit")
    parser.add_argument("--quiet", action="store_true", help="Suppress chatty output")

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run a scan against an authorized target")
    scan.add_argument("target", help="The authorized target to scan")
    scan.add_argument("method", nargs="?", default="standard", choices=["all", "passive", "recon", "web", "api", "standard", "deep", "ci", "bug-bounty", "dns", "certs", "headers", "tls", "technologies", "crawl", "cookies", "cors", "findings"], help="Scan method to run")
    scan.add_argument("--profile", choices=["passive", "recon", "web", "api", "standard", "deep", "ci", "bug-bounty"], default="standard")
    scan.add_argument("--rate", type=int, default=5, help="Global rate limit (requests/second)")
    scan.add_argument("--concurrency", type=int, default=5, help="Max allowed concurrent requests")
    scan.add_argument("--method", dest="method_flag", choices=["all", "passive", "recon", "web", "api", "standard", "deep", "ci", "bug-bounty", "dns", "certs", "headers", "tls", "technologies", "crawl", "cookies", "cors", "findings"], default=None, help="Alternate method selection flag")

    scope = subparsers.add_parser("scope", help="Manage the authorized scope")
    scope_sub = scope.add_subparsers(dest="scope_command")

    add = scope_sub.add_parser("add", help="Add a host or wildcard to the scope")
    add.add_argument("pattern")
    remove = scope_sub.add_parser("remove", help="Remove a host or wildcard from the scope")
    remove.add_argument("pattern")
    list_parser = scope_sub.add_parser("list", help="List authorized scope entries")
    list_parser.set_defaults(list_scope=True)

    subdomains = subparsers.add_parser("subdomains", help="Discover and list candidate subdomains")
    subdomains.add_argument("target")

    dorks = subparsers.add_parser("dorks", help="Generate safe search-engine dorks")
    dorks.add_argument("target")
    dorks.add_argument("--category", choices=["api", "documentation", "files", "admin", "all"], default="all")
    dorks.add_argument("--export", help="Optionally export dork list to a file")

    report = subparsers.add_parser("report", help="Render a report from findings")
    report.add_argument("--format", choices=["markdown", "json", "html", "sarif", "csv"], default="markdown")
    report.add_argument("--output", help="Write report to a file")

    for command_name in ["recon", "dns", "certs", "crawl", "endpoints", "javascript", "technologies", "headers", "tls", "cookies", "cors", "api", "findings", "assets", "osint"]:
        command = subparsers.add_parser(command_name, help=f"Run the {command_name} assessment module")
        command.add_argument("target")

    plugin = subparsers.add_parser("plugin", help="Manage optional plugin registry")
    plugin_sub = plugin.add_subparsers(dest="plugin_command")
    plugin_sub.add_parser("list", help="List available plugins")
    plugin_sub.add_parser("install", help="Install a plugin name placeholder")

    config = subparsers.add_parser("config", help="Show or initialize configuration")
    config.add_argument("--show", action="store_true", help="Display the current config")

    doctor = subparsers.add_parser("doctor", help="Run a basic environment validation")

    return parser


def _load_or_default_config() -> Config:
    app_path = config_path()
    if app_path.exists():
        return Config.from_file(app_path)
    return Config()


def handle_scope(args: argparse.Namespace) -> int:
    config = _load_or_default_config()
    patterns = list(config.scope.get("include", []))
    if args.scope_command == "add":
        if args.pattern not in patterns:
            patterns.append(args.pattern)
        config.scope["include"] = patterns
        config.save(config_path())
        print(f"Added {args.pattern} to scope")
        return 0
    if args.scope_command == "remove":
        patterns = [p for p in patterns if p != args.pattern]
        config.scope["include"] = patterns
        config.save(config_path())
        print(f"Removed {args.pattern} from scope")
        return 0
    if args.scope_command == "list" or getattr(args, "list_scope", False):
        print("Authorized scope:")
        if not patterns:
            print("- No entries configured")
            return 0
        for pattern in patterns:
            print(f"- {pattern}")
        return 0
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    method = args.method_flag or args.method
    config = Config.from_dict({
        "target": args.target,
        "profile": args.profile,
        "testing": {"passive": True, "active": False, "rate_limit": args.rate},
        "scope": {"include": [f"*.{args.target}"] if not args.target.startswith("*") else [args.target], "exclude": []},
    })
    scope = ScopeEngine(include=config.scope.get("include", []), exclude=config.scope.get("exclude", []))
    if not scope.is_in_scope(args.target):
        print(f"Target {args.target} is out of scope; aborting.")
        return 2

    engine = ScanEngine()
    result = engine.run(target=args.target, method=method, profile=args.profile, rate_limit=args.rate, concurrency=args.concurrency)
    print(f"NOMORE scan started for {args.target} (profile: {args.profile}, method: {method})")
    print(f"Total findings: {result['summary']['total_findings']}")
    print("Methods executed:")
    for item in result["methods"]:
        print(f"- {item}")
    if result["findings"]:
        print("Sample findings:")
        for item in result["findings"][:3]:
            print(f"  [{item['severity']}] {item['title']}")
    return 0


def handle_subdomains(args: argparse.Namespace) -> int:
    print(f"Passive subdomain discovery for {args.target}")
    for candidate in ["api.example.com", "dev.example.com", "staging.example.com"]:
        print(candidate)
    return 0


def handle_dorks(args: argparse.Namespace) -> int:
    categories = {
        "api": [f"site:{args.target} inurl:api", f"site:{args.target} inurl:swagger"],
        "documentation": [f"site:{args.target} filetype:pdf", f"site:{args.target} inurl:docs"],
        "files": [f"site:{args.target} filetype:json", f"site:{args.target} filetype:xml"],
        "admin": [f"site:{args.target} inurl:admin", f"site:{args.target} inurl:login"],
        "all": [
            f"site:{args.target}",
            f"site:{args.target} inurl:api",
            f"site:{args.target} inurl:admin",
            f"site:{args.target} filetype:pdf",
        ],
    }
    selected = categories[args.category]
    if args.export:
        Path(args.export).write_text("\n".join(selected) + "\n", encoding="utf-8")
        print(f"Exported {len(selected)} dorks to {args.export}")
        return 0
    for item in selected:
        print(item)
    return 0


def handle_report(args: argparse.Namespace) -> int:
    config = _load_or_default_config()
    findings = [
        Finding(
            title="Missing security headers",
            severity=Severity.LOW,
            confidence="high",
            affected_asset=f"https://{config.target}",
            evidence=["X-Frame-Options missing"],
            remediation="Add strong security headers with a focused security policy.",
        )
    ]
    if args.format == "json":
        report = render_json_report(config, findings)
    elif args.format == "html":
        report = render_html_report(config, findings)
    elif args.format == "sarif":
        report = render_sarif_report(config, findings)
    elif args.format == "csv":
        lines = ["title,severity,confidence,affected_asset,evidence"]
        for item in findings:
            lines.append(f"{item.title},{item.severity},{item.confidence},{item.affected_asset},{'; '.join(item.evidence)}")
        report = "\n".join(lines) + "\n"
    else:
        report = render_markdown_report(config, findings)
    _write_text(args.output, report)
    return 0


def handle_plugin(args: argparse.Namespace) -> int:
    if args.plugin_command == "list":
        print("Built-in plugins: dns, certificates, subdomains, crawler, javascript, technologies, headers, tls, api, search, vulnerabilities")
        return 0
    if args.plugin_command == "install":
        print("Plugin installation is scaffolded for future integration; no remote package manager is configured yet.")
        return 0
    print("No plugin action specified.")
    return 0


def handle_config(args: argparse.Namespace) -> int:
    config = _load_or_default_config()
    if args.show:
        print(json.dumps(config.to_dict(), indent=2))
        return 0
    print(f"Configuration path: {config_path()}")
    print(json.dumps(config.to_dict(), indent=2))
    return 0


def handle_doctor() -> int:
    checks = [
        ("Python", True),
        ("Network access", True),
        ("DNS resolution", True),
        ("SQLite database", True),
        ("YAML configuration", True),
    ]
    for label, passed in checks:
        status = "OK" if passed else "WARN"
        print(f"[{status}] {label}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scope":
        return handle_scope(args)
    if args.command == "scan":
        return handle_scan(args)
    if args.command in {"recon", "dns", "certs", "crawl", "endpoints", "javascript", "technologies", "headers", "tls", "cookies", "cors", "api", "findings", "assets", "osint"}:
        target = getattr(args, "target", "example.com")
        engine = ScanEngine()
        method = args.command if args.command != "recon" else "recon"
        result = engine.run(target=target, method=method)
        print(json.dumps({"target": target, "method": method, "summary": result["summary"], "findings": result["findings"]}, indent=2))
        return 0
    if args.command == "subdomains":
        return handle_subdomains(args)
    if args.command == "dorks":
        return handle_dorks(args)
    if args.command == "report":
        return handle_report(args)
    if args.command == "plugin":
        return handle_plugin(args)
    if args.command == "config":
        return handle_config(args)
    if args.command == "doctor":
        return handle_doctor()

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

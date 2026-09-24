from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

from . import __version__
from .config import Config, config_dir, config_path
from .database import ScanDatabase
from .models import SEVERITY_ORDER, Severity
from .reporting import REPORT_FORMATS, render_report
from .scan import ScanEngine
from .scope import ScopeEngine

SCAN_METHODS = ["all", "passive", "recon", "web", "api", "standard", "deep", "ci", "bug-bounty",
                "dns", "certs", "headers", "tls", "technologies", "crawl", "cookies", "cors", "subdomains", "findings"]
IMPLEMENTED_MODULES = ["recon", "dns", "certs", "crawl", "technologies", "headers", "tls", "cookies", "cors", "api"]
NOT_IMPLEMENTED = {
    "endpoints": "not implemented yet; try `nomore crawl <target>` or `nomore api <target>`",
    "javascript": "not implemented yet",
    "assets": "not implemented yet",
    "osint": "not implemented yet",
    "findings": "not a scan module; use `nomore report` to view findings from a saved scan",
}


def _write_text(path: str | None, content: str) -> None:
    if not path:
        print(content)
        return
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    print(f"Report written to {output}")


def _add_run_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rate", type=int, default=None, help="Global rate limit in requests/second (default: from config, else 5)")
    parser.add_argument("--concurrency", type=int, default=5, help="Reserved for future parallel checks")
    parser.add_argument("--active", action="store_true", help="Allow active probes (for example well-known API doc paths)")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates (lab targets only)")
    parser.add_argument("--no-save", action="store_true", help="Do not store this scan in the local history")
    parser.add_argument("--fail-on", type=str.upper, choices=SEVERITY_ORDER, default=None,
                        help="Exit with status 1 if any finding is at or above this severity (case-insensitive)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nomore",
        description="NOMORE — Next-Generation Web Security & OSINT CLI",
    )
    parser.add_argument("--version", action="store_true", help="Show NOMORE version and exit")
    parser.add_argument("--quiet", action="store_true", help="Suppress chatty output")

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run a scan against an authorized target")
    scan.add_argument("target", help="Host or URL. It must be inside the configured scope")
    scan.add_argument("method", nargs="?", default="standard", choices=SCAN_METHODS, help="Scan method to run")
    scan.add_argument("--profile", choices=["passive", "recon", "web", "api", "standard", "deep", "ci", "bug-bounty"], default="standard")
    scan.add_argument("--method", dest="method_flag", choices=SCAN_METHODS, default=None, help="Alternate method selection flag")
    _add_run_options(scan)

    scope = subparsers.add_parser("scope", help="Manage the authorized scope")
    scope_sub = scope.add_subparsers(dest="scope_command")
    add = scope_sub.add_parser("add", help="Authorize a host or wildcard")
    add.add_argument("pattern")
    exclude = scope_sub.add_parser("exclude", help="Explicitly exclude a host or wildcard")
    exclude.add_argument("pattern")
    remove = scope_sub.add_parser("remove", help="Remove a host or wildcard from the scope")
    remove.add_argument("pattern")
    list_parser = scope_sub.add_parser("list", help="List authorized scope entries")
    list_parser.set_defaults(list_scope=True)

    subdomains = subparsers.add_parser("subdomains", help="Discover candidate subdomains from certificate transparency")
    subdomains.add_argument("target")

    dorks = subparsers.add_parser("dorks", help="Generate safe search-engine dorks")
    dorks.add_argument("target")
    dorks.add_argument("--category", choices=["api", "documentation", "files", "admin", "all"], default="all")
    dorks.add_argument("--export", help="Optionally export dork list to a file")

    report = subparsers.add_parser("report", help="Render a report from a saved scan")
    report.add_argument("--format", choices=REPORT_FORMATS, default="markdown")
    report.add_argument("--output", help="Write report to a file")
    report.add_argument("--scan", default="latest", help="Scan id (or unique prefix); default: latest")
    report.add_argument("--target", help="With --scan latest, use the latest scan of this target")

    history = subparsers.add_parser("history", help="List saved scans")
    history.add_argument("--target")
    history.add_argument("--limit", type=int, default=20)

    diff = subparsers.add_parser("diff", help="Compare two saved scans (default: the two most recent)")
    diff.add_argument("old", nargs="?")
    diff.add_argument("new", nargs="?")
    diff.add_argument("--target", help="Restrict the default comparison to one target")

    for command_name in IMPLEMENTED_MODULES:
        command = subparsers.add_parser(command_name, help=f"Run the {command_name} assessment module")
        command.add_argument("target")
        _add_run_options(command)
    for command_name in NOT_IMPLEMENTED:
        command = subparsers.add_parser(command_name, help=f"{command_name} (not implemented yet)")
        command.add_argument("target", nargs="?")

    plugin = subparsers.add_parser("plugin", help="Manage optional plugin registry")
    plugin_sub = plugin.add_subparsers(dest="plugin_command")
    plugin_sub.add_parser("list", help="List available plugins")
    plugin_sub.add_parser("install", help="Install a plugin name placeholder")

    config = subparsers.add_parser("config", help="Show or initialize configuration")
    config.add_argument("--show", action="store_true", help="Display the current config")

    subparsers.add_parser("doctor", help="Run an environment validation")

    return parser


def _load_or_default_config() -> Config:
    app_path = config_path()
    if app_path.exists():
        return Config.from_file(app_path)
    return Config()


# -- scope ---------------------------------------------------------------------
def handle_scope(args: argparse.Namespace) -> int:
    config = _load_or_default_config()
    include = list(config.scope.get("include", []))
    exclude = list(config.scope.get("exclude", []))
    if args.scope_command == "add":
        if args.pattern not in include:
            include.append(args.pattern)
        config.scope["include"] = include
        config.save(config_path())
        print(f"Added {args.pattern} to scope")
        return 0
    if args.scope_command == "exclude":
        if args.pattern not in exclude:
            exclude.append(args.pattern)
        config.scope["exclude"] = exclude
        config.save(config_path())
        print(f"Excluded {args.pattern} from scope")
        return 0
    if args.scope_command == "remove":
        config.scope["include"] = [p for p in include if p != args.pattern]
        config.scope["exclude"] = [p for p in exclude if p != args.pattern]
        config.save(config_path())
        print(f"Removed {args.pattern} from scope")
        return 0
    if args.scope_command == "list" or getattr(args, "list_scope", False):
        print("Authorized scope:")
        if not include:
            print("- No entries configured")
        for pattern in include:
            print(f"- {pattern}")
        if exclude:
            print("Excluded:")
            for pattern in exclude:
                print(f"- {pattern}")
        return 0
    return 0


# -- scanning ------------------------------------------------------------------
def _run_scan(args: argparse.Namespace, target: str, method: str, profile: str, save: bool = True):
    """Shared by `scan`, the module commands, and `subdomains`. Returns (result, exit_code)."""
    config = _load_or_default_config()
    scope = ScopeEngine(config.scope.get("include", []), config.scope.get("exclude", []), strict=True)
    if not scope.is_target_in_scope(target):
        print(f"Target {target} is out of scope; aborting.", file=sys.stderr)
        if not scope.include:
            print("No scope is configured. Authorize the target first: nomore scope add <host>", file=sys.stderr)
        return None, 2

    rate = getattr(args, "rate", None) or int(config.testing.get("rate_limit", 5))
    active = bool(getattr(args, "active", False) or config.testing.get("active", False))
    engine = ScanEngine(scope, active=active, verify_tls=not getattr(args, "insecure", False))
    result = engine.run(target=target, method=method, profile=profile, rate_limit=rate,
                        concurrency=getattr(args, "concurrency", 5))
    if save and not getattr(args, "no_save", False):
        try:
            ScanDatabase().save_scan(result)
        except sqlite3.Error as error:
            print(f"Warning: could not save scan history: {error}", file=sys.stderr)
    return result, 0


EXIT_INCOMPLETE = 3


def _finish(args: argparse.Namespace, result: dict) -> int:
    """Exit codes: 1 = a finding met --fail-on, 3 = some checks failed (results incomplete), 0 = ok.

    Failed checks are always reported on stderr, even with --quiet, so an unreachable
    target can never look like a clean pass in CI.
    """
    for error in result["errors"]:
        print(f"! {error['method']} failed: {error['error']}", file=sys.stderr)
    threshold = getattr(args, "fail_on", None)
    if threshold and any(Severity(f["severity"]).rank >= Severity(threshold).rank for f in result["findings"]):
        return 1
    if result["errors"]:
        print(f"Scan incomplete: {len(result['errors'])} check(s) failed; results may be missing findings.", file=sys.stderr)
        return EXIT_INCOMPLETE
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    method = args.method_flag or args.method
    result, code = _run_scan(args, args.target, method, args.profile)
    if result is None:
        return code
    if not args.quiet:
        counts = result["summary"]["severity_counts"]
        print(f"NOMORE scan of {args.target} (profile: {args.profile}, method: {method})")
        print(f"Scan id: {result['scan_id']}")
        print(f"Requests made: {result['requests_made']}")
        print(f"Total findings: {result['summary']['total_findings']}  " +
              " ".join(f"{label}={counts[label]}" for label in reversed(SEVERITY_ORDER) if counts[label]))
        print("Methods executed:")
        for item in result["methods"]:
            print(f"- {item}")
        if result["findings"]:
            print("Top findings:")
            for item in result["findings"][:5]:
                print(f"  [{item['severity']}] {item['title']}")
    return _finish(args, result)


def handle_module(args: argparse.Namespace) -> int:
    result, code = _run_scan(args, args.target, args.command, args.command)
    if result is None:
        return code
    print(json.dumps({"target": args.target, "method": args.command, "summary": result["summary"],
                      "findings": result["findings"], "errors": result["errors"]}, indent=2))
    return _finish(args, result)


def handle_subdomains(args: argparse.Namespace) -> int:
    result, code = _run_scan(args, args.target, "subdomains", "recon", save=False)
    if result is None:
        return code
    print(f"Passive subdomain discovery for {args.target}")
    for error in result["errors"]:
        print(f"! {error['error']}", file=sys.stderr)
    names = [a["host"] for a in result["assets"] if a["type"] == "subdomain"]
    for name in names:
        print(name)
    if not names and not result["errors"]:
        print("(no in-scope subdomains found)")
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


# -- history / reporting ---------------------------------------------------------
def handle_report(args: argparse.Namespace) -> int:
    db = ScanDatabase()
    try:
        scan = db.get_scan(args.scan, target=args.target)
    except LookupError as error:
        print(str(error), file=sys.stderr)
        return 2
    if scan is None:
        print("No matching scan found. Run `nomore scan <target>` first.", file=sys.stderr)
        return 1
    config = Config(target=scan["target"], profile=scan["profile"])
    _write_text(args.output, render_report(args.format, config, scan["findings"]))
    return 0


def handle_history(args: argparse.Namespace) -> int:
    scans = ScanDatabase().list_scans(target=args.target, limit=args.limit)
    if not scans:
        print("No scans recorded yet.")
        return 0
    for item in scans:
        counts = item["summary"].get("severity_counts", {})
        worst = next((label for label in reversed(SEVERITY_ORDER) if counts.get(label)), "-")
        print(f"{item['scan_id'][:8]}  {item['started_at'][:19]}  {item['target']:<30} "
              f"{item['profile']:<10} findings={item['summary'].get('total_findings', 0):<3} worst={worst}")
    return 0


def handle_diff(args: argparse.Namespace) -> int:
    db = ScanDatabase()
    old_ref, new_ref = args.old, args.new
    if not old_ref and not new_ref:
        recent = db.list_scans(target=args.target, limit=2)
        if len(recent) < 2:
            print("Need at least two saved scans to compare.", file=sys.stderr)
            return 1
        new_ref, old_ref = recent[0]["scan_id"], recent[1]["scan_id"]
    elif not (old_ref and new_ref):
        print("Provide both scan ids, or neither.", file=sys.stderr)
        return 2
    try:
        diff = db.diff_scans(old_ref, new_ref)
    except LookupError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(f"Comparing {diff['old'][:8]} -> {diff['new'][:8]}")
    for label, key in (("older", "old_errors"), ("newer", "new_errors")):
        if diff[key]:
            print(f"Warning: the {label} scan had {diff[key]} failed check(s); its findings may be incomplete, "
                  "so 'fixed'/'new' results can be misleading.", file=sys.stderr)
    for label, key in (("New", "new_findings"), ("Fixed", "fixed_findings")):
        print(f"{label} findings: {len(diff[key])}")
        for item in diff[key]:
            print(f"  [{item.severity}] {item.title} ({item.affected_url or item.affected_asset})")
    print(f"Unchanged: {len(diff['unchanged_findings'])}")
    return 0


# -- misc ------------------------------------------------------------------------
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


def _doctor_checks() -> list[tuple[str, bool]]:
    checks: list[tuple[str, bool]] = [("Python >= 3.10", sys.version_info >= (3, 10))]
    try:
        import yaml  # noqa: F401
        checks.append(("YAML configuration (PyYAML)", True))
    except ImportError:
        checks.append(("YAML configuration (PyYAML)", False))
    try:
        directory = config_dir()
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory):
            pass
        checks.append((f"Config directory writable ({directory})", True))
    except OSError:
        checks.append(("Config directory writable", False))
    try:
        ScanDatabase().count_findings()
        checks.append(("SQLite database", True))
    except (sqlite3.Error, OSError):
        checks.append(("SQLite database", False))
    try:
        socket.getaddrinfo("example.com", 443)
        checks.append(("DNS resolution", True))
    except OSError:
        checks.append(("DNS resolution", False))
    return checks


def handle_doctor() -> int:
    failed = 0
    for label, passed in _doctor_checks():
        print(f"[{'OK' if passed else 'WARN'}] {label}")
        failed += 0 if passed else 1
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:  # e.g. `nomore report | head`
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0


def _main(argv: list[str] | None = None) -> int:
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
    if args.command in IMPLEMENTED_MODULES:
        return handle_module(args)
    if args.command in NOT_IMPLEMENTED:
        print(f"nomore {args.command}: {NOT_IMPLEMENTED[args.command]}", file=sys.stderr)
        return 1
    if args.command == "subdomains":
        return handle_subdomains(args)
    if args.command == "dorks":
        return handle_dorks(args)
    if args.command == "report":
        return handle_report(args)
    if args.command == "history":
        return handle_history(args)
    if args.command == "diff":
        return handle_diff(args)
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

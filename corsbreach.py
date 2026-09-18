#!/usr/bin/env python3
"""
corsbreach.py
=============

CORSBreach - CORS Misconfiguration Scanner
A pure Python 3 standard-library defensive security tool for identifying
and documenting CORS (Cross-Origin Resource Sharing) misconfigurations.

Intended for use against systems you are authorized to test, such as your
own applications or authorized labs (e.g. PortSwigger Web Security
Academy). See README.md for the full ethical-use statement.

Usage:
    python corsbreach.py --help
    python corsbreach.py --version
    python corsbreach.py scan <URL> [options]
    python corsbreach.py batch <FILE> [options]
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from core.http_client import HttpClient, HttpClientError
from core.scanner import Scanner, SCANNER_VERSION
from output.reporter import print_terminal_report, write_json_report

PROG_NAME = "corsbreach"
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

DEFAULT_CONFIG: Dict[str, Any] = {
    "timeout": 15,
    "user_agent": "CORSBreach/1.0",
    "test_origins": ["https://evil.example", "https://attacker.example", "null"],
    "follow_redirects": True,
    "verify_tls": True,
    "log_level": "INFO",
    "batch_delay_seconds": 1.0,
}

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class ConfigError(Exception):
    """Raised for a configuration problem that should abort the run cleanly."""


# --------------------------------------------------------------------------
# Configuration loading / validation
# --------------------------------------------------------------------------

def load_config(path: Optional[str]) -> Dict[str, Any]:
    """
    Load and validate a JSON config file, merged over DEFAULT_CONFIG.

    Never raises for a missing/malformed file - it logs a warning and falls
    back to defaults, per the project's error-handling requirements. Only
    raises ConfigError if the user explicitly named a config file with
    --config and it could not be read at all (so mistakes aren't silently
    swallowed), while an invalid *value* inside an existing file is
    corrected to its default instead of aborting the scan.
    """
    config = dict(DEFAULT_CONFIG)
    if not path:
        return config

    if not os.path.isfile(path):
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise ConfigError(f"Configuration file is invalid: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Configuration file is invalid: expected a JSON object.")

    config.update(raw)
    return _validate_config(config)


def _validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce/repair individual fields so a bad value never crashes the tool."""
    validated = dict(config)

    timeout = validated.get("timeout")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        validated["timeout"] = DEFAULT_CONFIG["timeout"]

    if not isinstance(validated.get("user_agent"), str) or not validated["user_agent"].strip():
        validated["user_agent"] = DEFAULT_CONFIG["user_agent"]

    origins = validated.get("test_origins")
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        validated["test_origins"] = DEFAULT_CONFIG["test_origins"]

    if not isinstance(validated.get("follow_redirects"), bool):
        validated["follow_redirects"] = DEFAULT_CONFIG["follow_redirects"]

    if not isinstance(validated.get("verify_tls"), bool):
        validated["verify_tls"] = DEFAULT_CONFIG["verify_tls"]

    level = validated.get("log_level")
    if not isinstance(level, str) or level.upper() not in VALID_LOG_LEVELS:
        validated["log_level"] = DEFAULT_CONFIG["log_level"]
    else:
        validated["log_level"] = level.upper()

    delay = validated.get("batch_delay_seconds")
    if not isinstance(delay, (int, float)) or delay < 0:
        validated["batch_delay_seconds"] = DEFAULT_CONFIG["batch_delay_seconds"]

    return validated


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def setup_logging(log_level: str) -> None:
    """
    Configure logging: DEBUG-and-up always goes to logs/corsbreach.log (full
    detail, including tracebacks), while the console only shows the level
    the user asked for. This is how tracebacks stay out of normal console
    output without being lost entirely.
    """
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_file = os.path.join(LOG_DIR, "corsbreach.log")
        file_handler: Optional[logging.Handler] = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
    except OSError:
        # Can't write logs (e.g. permission error) - continue with console-only logging.
        file_handler = None

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, log_level, logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    console_handler.setFormatter(fmt)

    root = logging.getLogger("corsbreach")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    root.addHandler(console_handler)
    if file_handler:
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def build_client(config: Dict[str, Any], timeout_override: Optional[float]) -> HttpClient:
    return HttpClient(
        timeout=timeout_override if timeout_override is not None else config["timeout"],
        user_agent=config["user_agent"],
        verify_tls=config["verify_tls"],
        follow_redirects=config["follow_redirects"],
    )


def cmd_scan(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    client = build_client(config, args.timeout)
    scanner = Scanner(client, test_origins=config["test_origins"])

    try:
        HttpClient.validate_url(args.url)
    except HttpClientError as exc:
        print(f"[ERROR] {exc}")
        return 1

    result = scanner.scan(args.url)
    print_terminal_report(result)

    if args.output:
        try:
            write_json_report(result, args.output)
            print(f"\nJSON report written to: {args.output}")
        except OSError as exc:
            print(f"[ERROR] Could not write JSON report: {exc}")
            return 1

    return 0 if result.target_status == "reachable" else 1


def _read_targets(path: str) -> List[str]:
    if not os.path.isfile(path):
        raise ConfigError(f"Target file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise ConfigError(f"Could not read target file: {exc}") from exc

    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def cmd_batch(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    try:
        targets = _read_targets(args.file)
    except ConfigError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if not targets:
        print("[ERROR] Target file contains no targets.")
        return 1

    client = build_client(config, args.timeout)
    scanner = Scanner(client, test_origins=config["test_origins"])
    results = []

    for index, target in enumerate(targets):
        try:
            HttpClient.validate_url(target)
        except HttpClientError as exc:
            print(f"[ERROR] Skipping invalid target '{target}': {exc}")
            continue

        result = scanner.scan(target)
        print_terminal_report(result)
        results.append(result)

        if index < len(targets) - 1:
            time.sleep(config["batch_delay_seconds"])

    if args.output:
        try:
            write_json_report(results, args.output)
            print(f"\nJSON report written to: {args.output}")
        except OSError as exc:
            print(f"[ERROR] Could not write JSON report: {exc}")
            return 1

    return 0 if results else 1


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    # --config and --log-level are defined on this shared parent so they can
    # appear either before the subcommand (`corsbreach.py --log-level DEBUG
    # scan <url>`) or after it (`corsbreach.py scan <url> --log-level DEBUG`),
    # matching both usage styles shown in the project's documentation.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="PATH", default=None, help="Path to a JSON configuration file.")
    common.add_argument("--log-level", choices=VALID_LOG_LEVELS, default=None, help="Console log verbosity.")

    parser = argparse.ArgumentParser(
        prog=PROG_NAME,
        description="CORSBreach - CORS Misconfiguration Scanner (defensive security tool).",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"CORSBreach {SCANNER_VERSION}")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a single target URL.", parents=[common])
    scan_parser.add_argument("url", help="Target URL, e.g. https://example.web-security-academy.net")
    scan_parser.add_argument("--timeout", type=float, default=None, help="Per-request timeout in seconds.")
    scan_parser.add_argument("--output", metavar="FILE", help="Write a JSON report to FILE.")

    batch_parser = subparsers.add_parser("batch", help="Scan every target listed in a file.", parents=[common])
    batch_parser.add_argument("file", help="Path to a text file with one target URL per line.")
    batch_parser.add_argument("--timeout", type=float, default=None, help="Per-request timeout in seconds.")
    batch_parser.add_argument("--output", metavar="FILE", help="Write a combined JSON report to FILE.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if args.log_level:
        config["log_level"] = args.log_level

    setup_logging(config["log_level"])
    logger = logging.getLogger("corsbreach.cli")
    logger.debug("Resolved configuration: %s", config)

    try:
        if args.command == "scan":
            return cmd_scan(args, config)
        if args.command == "batch":
            return cmd_batch(args, config)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        print("\n[ERROR] Interrupted by user.")
        return 130
    except Exception as exc:  # noqa: BLE001 - last-resort guard for normal users
        # Full traceback goes to the log file (DEBUG level); the console
        # only ever sees a clean, single-line error message.
        logger.debug("Unhandled exception", exc_info=True)
        print(f"[ERROR] An unexpected error occurred: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

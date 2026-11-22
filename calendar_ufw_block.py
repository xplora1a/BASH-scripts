#!/usr/bin/env python3
"""Find suspicious calendar requests in an Apache-style access log."""

import argparse
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
import gzip
import ipaddress
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple, Union


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
BLOCK_DURATION = timedelta(hours=24)


LOG_ENTRY_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<log_time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"'
)
LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
DATE_PATH_RE = re.compile(
    r"^/calendar/.*?exact_date~"
    r"(?P<timestamp>\d+)(?:/|\?|$)"
)


def shift_years(value: datetime, years: int) -> datetime:
    """Shift by calendar years, mapping leap day to February 28 if needed."""
    try:
        return value.replace(year=value.year + years)
    except ValueError:
        return value.replace(year=value.year + years, day=28)


def init_state(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS blocked_networks (
            network TEXT PRIMARY KEY,
            blocked_at TEXT NOT NULL,
            managed INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            device INTEGER NOT NULL,
            inode INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            last_log_time TEXT
        );
        """
    )
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(blocked_networks)")
    }
    if "managed" not in columns:
        connection.execute(
            "ALTER TABLE blocked_networks "
            "ADD COLUMN managed INTEGER NOT NULL DEFAULT 0"
        )
    connection.commit()


def tail_start_offset(path: Path, count: int) -> int:
    with path.open("rb") as log_file:
        log_file.seek(0, os.SEEK_END)
        end = position = log_file.tell()
        trailing_newline = False
        if end:
            log_file.seek(end - 1)
            trailing_newline = log_file.read(1) == b"\n"
        needed = count + int(trailing_newline)
        accumulated = b""
        chunk_size = 8192
        while position > 0 and accumulated.count(b"\n") < needed:
            read_size = min(chunk_size, position)
            position -= read_size
            log_file.seek(position)
            accumulated = log_file.read(read_size) + accumulated
        if accumulated.count(b"\n") < needed:
            return 0
        boundary = len(accumulated)
        for _ in range(needed):
            boundary = accumulated.rfind(b"\n", 0, boundary)
        return position + boundary + 1


def read_lines(path: Path, offset: int = 0) -> Tuple[List[str], int]:
    lines = []
    with path.open("rb") as log_file:
        log_file.seek(offset)
        end_offset = offset
        while raw_line := log_file.readline():
            if not raw_line.endswith(b"\n"):
                break
            lines.append(raw_line.decode("utf-8", errors="replace"))
            end_offset = log_file.tell()
        return lines, end_offset


def log_timestamp(line: str) -> Optional[datetime]:
    entry = LOG_ENTRY_RE.match(line)
    if entry is None:
        return None
    try:
        return datetime.strptime(entry.group("log_time"), LOG_TIME_FORMAT).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def rotated_logs(path: Path) -> Iterable[Path]:
    prefix = f"{path.name}."
    for candidate in path.parent.iterdir():
        suffix = candidate.name[len(prefix) :] if candidate.name.startswith(prefix) else ""
        if (
            candidate.is_file()
            and re.fullmatch(r"(?:\d+|-\d{4}-\d{2}-\d{2})(?:\.gz)?", suffix)
        ):
            yield candidate


def read_log_batch(
    path: Path, count: int, checkpoint: Optional[sqlite3.Row]
) -> Tuple[List[str], int, Optional[datetime], int, int]:
    stat = path.stat()
    if checkpoint is None:
        offset = tail_start_offset(path, count)
        lines, end_offset = read_lines(path, offset)
        return lines, end_offset, None, stat.st_dev, stat.st_ino

    last_time = (
        datetime.fromisoformat(checkpoint["last_log_time"])
        if checkpoint["last_log_time"]
        else None
    )
    same_file = (
        stat.st_dev == checkpoint["device"]
        and stat.st_ino == checkpoint["inode"]
        and stat.st_size >= checkpoint["offset"]
    )
    if same_file:
        lines, end_offset = read_lines(path, checkpoint["offset"])
        return lines, end_offset, last_time, stat.st_dev, stat.st_ino

    for candidate in rotated_logs(path):
        candidate_stat = candidate.stat()
        if (
            candidate_stat.st_dev == checkpoint["device"]
            and candidate_stat.st_ino == checkpoint["inode"]
        ):
            lines, _ = read_lines(candidate, checkpoint["offset"])
            current_lines, end_offset = read_lines(path)
            return (
                lines + current_lines,
                end_offset,
                last_time,
                stat.st_dev,
                stat.st_ino,
            )

    # If the old inode was removed or compressed, use access-log timestamps
    # to resume from the available rotated logs and the new active log.
    lines = []
    current_offset = 0
    candidates = list(rotated_logs(path))
    candidates.append(path)
    for candidate in candidates:
        if candidate.suffix == ".gz":
            with gzip.open(candidate, "rt", encoding="utf-8", errors="replace") as log_file:
                candidate_lines = list(log_file)
        else:
            candidate_lines, candidate_offset = read_lines(candidate)
            if candidate == path:
                current_offset = candidate_offset
        for line in candidate_lines:
            timestamp = log_timestamp(line)
            if last_time is None or (
                timestamp is not None and timestamp >= last_time
            ):
                lines.append(line)
    return lines, current_offset, last_time, stat.st_dev, stat.st_ino


def find_networks(
    lines: Iterable[str], now: datetime
) -> Tuple[Dict[Network, Counter], int]:
    oldest_allowed = shift_years(now, -2)
    newest_allowed = shift_years(now, 2)
    network_counts: Dict[Network, Counter] = {}
    skipped_non_global = 0

    for line in lines:
        entry = LOG_ENTRY_RE.match(line)
        if entry is None:
            continue

        request_parts = entry.group("request").split(maxsplit=2)
        if len(request_parts) < 2 or request_parts[0] != "GET":
            continue

        date_path = DATE_PATH_RE.match(request_parts[1])
        if date_path is None:
            continue

        try:
            request_date = datetime.fromtimestamp(
                int(date_path.group("timestamp")), timezone.utc
            )
        except (OverflowError, OSError, ValueError):
            continue

        if oldest_allowed <= request_date <= newest_allowed:
            continue

        try:
            address = ipaddress.ip_address(entry.group("ip"))
        except ValueError:
            continue

        if not address.is_global:
            skipped_non_global += 1
            continue

        prefix = 24 if address.version == 4 else 48
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        network_counts.setdefault(network, Counter())[address] += 1

    return network_counts, skipped_non_global


def existing_denied_networks(ufw: str) -> Set[Network]:
    result = subprocess.run(
        [ufw, "status"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Could not read UFW status: {details}")

    denied = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        try:
            deny_position = fields.index("DENY")
        except ValueError:
            continue

        for field in fields[deny_position + 1 :]:
            try:
                denied.add(ipaddress.ip_network(field, strict=False))
            except ValueError:
                continue

    return denied


def is_covered_by(network: Network, networks: Iterable[Network]) -> bool:
    return any(
        network.version == existing.version and network.subnet_of(existing)
        for existing in networks
    )


def save_checkpoint(
    connection: sqlite3.Connection,
    device: int,
    inode: int,
    offset: int,
    last_log_time: Optional[datetime],
) -> None:
    connection.execute(
        """
        INSERT INTO checkpoint (id, device, inode, offset, last_log_time)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            device = excluded.device,
            inode = excluded.inode,
            offset = excluded.offset,
            last_log_time = excluded.last_log_time
        """,
        (
            device,
            inode,
            offset,
            last_log_time.isoformat() if last_log_time else None,
        ),
    )
    connection.commit()


def expire_blocks(
    ufw: str,
    connection: sqlite3.Connection,
    now: datetime,
    dry_run: bool = False,
) -> Tuple[int, Set[Network]]:
    cutoff = now - BLOCK_DURATION
    expired = []
    for row in connection.execute(
        "SELECT network, blocked_at FROM blocked_networks WHERE managed = 1"
    ):
        try:
            blocked_at = datetime.fromisoformat(row["blocked_at"])
        except ValueError:
            print(
                f"Invalid block timestamp for {row['network']}; "
                "leaving its UFW rule unchanged.",
                file=sys.stderr,
            )
            return 1
        if blocked_at.tzinfo is None:
            blocked_at = blocked_at.replace(tzinfo=timezone.utc)
        if blocked_at <= cutoff:
            expired.append(ipaddress.ip_network(row["network"]))

    if not expired:
        return 0, set()

    failures = 0
    expired_networks = set(expired)
    for network in expired:
        rule = ["--force", "delete", "deny", "from", str(network), "to", "any"]
        if dry_run:
            print("sudo ufw " + " ".join(rule))
            continue

        result = subprocess.run(
            [ufw, *rule],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print(f"Expired UFW deny rule: {network}")
            connection.execute(
                "DELETE FROM blocked_networks WHERE network = ? AND managed = 1",
                (str(network),),
            )
            connection.commit()
        else:
            details = result.stderr.strip() or result.stdout.strip()
            print(
                f"Failed to expire {network}: {details}",
                file=sys.stderr,
            )
            failures += 1

    return (1 if failures else 0), expired_networks


def apply_blocks(
    networks: Iterable[Network],
    connection: sqlite3.Connection,
    dry_run: bool = False,
) -> int:
    if dry_run:
        ufw = "ufw"
        print("Dry run: no UFW commands will be executed.")
        print(
            "UFW status is not checked; proposed additions may include "
            "rules already present outside this script."
        )
    else:
        if os.geteuid() != 0:
            print(
                "Applying UFW rules requires root; rerun with sudo.",
                file=sys.stderr,
            )
            return 2

        ufw = shutil.which("ufw")
        if ufw is None:
            print("Could not find the ufw command in PATH.", file=sys.stderr)
            return 2

    expiry_result, expired = expire_blocks(
        ufw, connection, datetime.now(timezone.utc), dry_run
    )
    if expiry_result != 0:
        return 1

    if dry_run:
        denied = {
            ipaddress.ip_network(row["network"])
            for row in connection.execute(
                "SELECT network FROM blocked_networks WHERE managed = 1"
            )
        }
    else:
        denied = existing_denied_networks(ufw)
    denied.difference_update(expired)
    failures = 0
    for network in networks:
        if is_covered_by(network, denied):
            managed = connection.execute(
                "SELECT 1 FROM blocked_networks "
                "WHERE network = ? AND managed = 1",
                (str(network),),
            ).fetchone()
            if managed:
                if dry_run:
                    print(f"Would refresh 24-hour UFW block: {network}")
                else:
                    connection.execute(
                        "UPDATE blocked_networks SET blocked_at = ? "
                        "WHERE network = ? AND managed = 1",
                        (datetime.now(timezone.utc).isoformat(), str(network)),
                    )
                    connection.commit()
                    print(f"Refreshed 24-hour UFW block: {network}")
            else:
                print(f"Already denied by an existing UFW rule: {network}")
            continue

        if dry_run:
            print(f"sudo ufw prepend deny from {network} to any")
            denied.add(network)
            continue

        result = subprocess.run(
            [ufw, "prepend", "deny", "from", str(network), "to", "any"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print(f"Added UFW deny rule: {network}")
            denied.add(network)
            connection.execute(
                "INSERT OR REPLACE INTO blocked_networks "
                "(network, blocked_at, managed) VALUES (?, ?, 1)",
                (str(network), datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()
        else:
            details = result.stderr.strip() or result.stdout.strip()
            print(f"Failed to block {network}: {details}", file=sys.stderr)
            failures += 1

    return 1 if failures else 0


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Find old/future calendar requests in recent log entries, track "
            "progress across runs, and optionally deny their source networks."
        )
    )
    parser.add_argument("logfile", type=Path, help="Apache-style access log")
    parser.add_argument(
        "--lines",
        type=positive_integer,
        default=1000,
        help="number of latest lines to scan on the first run (default: 1000)",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help="SQLite state file (default: <logfile>.calendar-ufw.sqlite3)",
    )
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "--apply",
        action="store_true",
        help=(
            "add UFW deny rules and expire this script's rules 24 hours after "
            "the latest matching request; without this option, only show a preview"
        ),
    )
    action_group.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "print the UFW add/delete commands without changing rules, timers, "
            "or log progress"
        ),
    )
    args = parser.parse_args()

    state_path = args.state_file or args.logfile.with_name(
        args.logfile.name + ".calendar-ufw.sqlite3"
    )
    connection = None
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(state_path)
        connection.row_factory = sqlite3.Row
        init_state(connection)
        checkpoint = connection.execute(
            "SELECT device, inode, offset, last_log_time FROM checkpoint WHERE id = 1"
        ).fetchone()
        lines, end_offset, last_log_time, device, inode = read_log_batch(
            args.logfile, args.lines, checkpoint
        )
    except OSError as error:
        if connection is not None:
            connection.close()
        print(f"Could not read log or state file: {error}", file=sys.stderr)
        return 2
    except (sqlite3.Error, EOFError, gzip.BadGzipFile) as error:
        if connection is not None:
            connection.close()
        print(f"Could not read log or state file: {error}", file=sys.stderr)
        return 2

    timestamps = [
        timestamp
        for line in lines
        if (timestamp := log_timestamp(line)) is not None
    ]
    if timestamps:
        newest_timestamp = max(timestamps)
        if last_log_time is None or newest_timestamp > last_log_time:
            last_log_time = newest_timestamp

    networks, skipped_non_global = find_networks(
        lines, datetime.now(timezone.utc)
    )
    if not networks:
        print("No qualifying public IP addresses found.")
    else:
        for network, occurrences in sorted(
            networks.items(),
            key=lambda item: (
                item[0].version,
                int(item[0].network_address),
            ),
        ):
            source_addresses = ", ".join(
                str(address) + (f" x{count}" if count > 1 else "")
                for address, count in sorted(
                    occurrences.items(),
                    key=lambda item: int(item[0]),
                )
            )
            match_count = sum(occurrences.values())
            print(
                f"{source_addresses} -> {network} "
                f"({match_count} matching request(s))"
            )

    if skipped_non_global:
        print(
            f"Skipped {skipped_non_global} matching request(s) with "
            "non-public source addresses."
        )

    if args.apply or args.dry_run:
        try:
            result = apply_blocks(
                sorted(
                    networks,
                    key=lambda item: (
                        item.version,
                        int(item.network_address),
                    ),
                ),
                connection,
                dry_run=args.dry_run,
            )
        except (OSError, RuntimeError) as error:
            print(f"Could not inspect or update UFW: {error}", file=sys.stderr)
            connection.close()
            return 2
        if result != 0:
            connection.close()
            return result

    if args.apply:
        save_checkpoint(
            connection, device, inode, end_offset, last_log_time
        )

    if networks and not args.dry_run:
        print("Preview only; pass --apply to add these UFW rules.")
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

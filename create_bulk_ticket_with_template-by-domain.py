#!/usr/bin/env python3
import argparse
import csv
import logging
import os
import sys
import time
from collections import defaultdict
from string import Template
from typing import Dict, List, Sequence, Set, Tuple

import rt
import sphinxapi
from pyurlabuse import PyURLAbuse

import config as cfg


LOGGER = logging.getLogger(__name__)
DEFAULT_QUEUE_ID = 5
PYURLABUSE_RETRY_DELAY = 5
RT_OPEN_STATUSES = {"open", "new"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create one RT ticket per ASN from a CSV file and link it to an incident."
    )
    parser.add_argument("incident_id", help="Parent incident ticket ID")
    parser.add_argument("template_name", help="Template file name")
    parser.add_argument("csv_file", help="CSV input file")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Send only to the debug recipient and stop after the first ticket",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview actions without creating or linking RT tickets",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview actions without creating or linking RT tickets",
    )
    parser.add_argument(
        "--debug-recipient",
        default="sascha@rommelfangen.de",
        help="Recipient used in debug mode",
    )
    return parser.parse_args()


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def resolve_template_path(template_name: str) -> str:
    script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    return os.path.join(script_dir, template_name)


def create_tracker() -> rt.Rt:
    tracker = rt.Rt(cfg.rt_url, cfg.rt_user, cfg.rt_pass, verify_cert=False)
    tracker.login()
    return tracker


def create_sphinx_client() -> sphinxapi.SphinxClient:
    client = sphinxapi.SphinxClient()
    client.SetServer(cfg.sphinx_server, cfg.sphinx_port)
    client.SetMatchMode(2)
    return client


def is_ticket_open(tracker: rt.Rt, ticket_id: int) -> bool:
    try:
        rt_response = tracker.get_ticket(ticket_id)
    except Exception as exc:
        LOGGER.warning("Could not read ticket %s: %s", ticket_id, exc)
        return False

    return rt_response.get("Status") in RT_OPEN_STATUSES


def open_tickets_for_url(tracker: rt.Rt, client: sphinxapi.SphinxClient, url: str) -> List[int]:
    query = f'"{url}"'
    result = client.Query(query)
    matches = result.get("matches", []) if result else []

    open_ticket_ids: List[int] = []
    for match in matches:
        ticket_id = match.get("id")
        if ticket_id and is_ticket_open(tracker, ticket_id):
            open_ticket_ids.append(ticket_id)

    return open_ticket_ids


def load_template(template_path: str) -> Tuple[str, Template]:
    try:
        with open(template_path, "r", encoding="utf-8") as handle:
            subject = handle.readline().rstrip()
            content = handle.read()
    except OSError as exc:
        raise RuntimeError(f"Could not open template file ({template_path}): {exc}") from exc

    return subject, Template(content)


def load_csv_rows(csv_file: str) -> Tuple[str, List[List[str]]]:
    try:
        with open(csv_file, "r", encoding="utf-8", newline="") as handle:
            headerline = handle.readline().strip()
    except OSError as exc:
        raise RuntimeError(f"Could not open CSV file ({csv_file}): {exc}") from exc

    if "Format" not in headerline:
        raise RuntimeError("Header doesn't contain 'Format' string")

    with open(csv_file, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))

    return headerline, rows


def group_rows_by_asn(rows: Sequence[Sequence[str]], exclude_list: Set[str]) -> Dict[str, List[List[str]]]:
    grouped_rows: Dict[str, List[List[str]]] = defaultdict(list)

    for row in rows:
        if not row:
            continue
        if "Format" in row[0]:
            continue
        if len(row) < 2:
            LOGGER.warning("Skipping malformed row: %s", row)
            continue
        if row[1] in exclude_list:
            LOGGER.info("Skipping excluded row: %s", row)
            continue

        asn = row[0].strip()
        if not asn:
            LOGGER.warning("Skipping row without ASN: %s", row)
            continue

        grouped_rows[asn].append(list(row))

    return dict(grouped_rows)


def lookup_recipients(asn: str) -> Tuple[List[str], object]:
    pyurlabuse = PyURLAbuse()
    response = pyurlabuse.run_query(asn, with_digest=True)
    time.sleep(PYURLABUSE_RETRY_DELAY)
    response = pyurlabuse.run_query(asn, with_digest=True)

    digest = response.get("digest", [])
    recipients = ["".join(email) for email in digest[1]] if len(digest) > 1 else []
    recipient_asns = digest[2] if len(digest) > 2 else None

    unique_recipients = sorted({recipient for recipient in recipients if recipient})
    return unique_recipients, recipient_asns


def build_detail_text(headerline: str, rows_for_asn: Sequence[Sequence[str]]) -> str:
    details = [headerline]
    for row in rows_for_asn:
        details.append(" " + ",".join(row))
    return "\n".join(details)


def create_ticket_for_asn(
    tracker: rt.Rt,
    incident_id: str,
    queue_id: int,
    asn: str,
    recipients: Sequence[str],
    subject_prefix: str,
    body: str,
    dry_run: bool = False,
) -> int | None:
    subject = f"{subject_prefix} ({asn})"
    requestors = ", ".join(recipients)

    if dry_run:
        LOGGER.info("[DRY-RUN] Would create ticket for ASN %s", asn)
        LOGGER.info("[DRY-RUN] Queue: %s", queue_id)
        LOGGER.info("[DRY-RUN] Subject: %s", subject)
        LOGGER.info("[DRY-RUN] Requestors: %s", requestors)
        LOGGER.info("[DRY-RUN] Incident link target: %s", incident_id)
        LOGGER.info("[DRY-RUN] Body preview:\n%s", body)
        return None

    ticket_id = tracker.create_ticket(
        Queue=queue_id,
        Subject=subject,
        Text=body,
        Requestors=requestors,
    )
    LOGGER.info("Ticket created for ASN %s: %s", asn, ticket_id)

    tracker.edit_ticket_links(ticket_id, MemberOf=incident_id)
    LOGGER.info("Linked ticket %s to incident %s", ticket_id, incident_id)

    return ticket_id


def main() -> int:
    setup_logging()
    args = parse_args()

    if args.debug and args.dry_run:
        LOGGER.info("Both --debug and --dry-run are enabled")

    if args.debug and args.dry_run:
        LOGGER.info("Both --debug and --dry-run are enabled")

    template_path = resolve_template_path(args.template_name)
    subject_prefix, template = load_template(template_path)
    headerline, rows = load_csv_rows(args.csv_file)
    grouped_rows = group_rows_by_asn(rows, set(cfg.known_good_excludelist))

    if not grouped_rows:
        LOGGER.warning("No eligible rows found in CSV file")
        return 0

    tracker = create_tracker()
    client = create_sphinx_client()

    for asn in sorted(grouped_rows):
        LOGGER.info("Processing ASN %s", asn)
        rows_for_asn = grouped_rows[asn]

        try:
            recipients, recipient_asns = lookup_recipients(asn)
        except Exception as exc:
            LOGGER.error("PyURLAbuse lookup failed for ASN %s: %s", asn, exc)
            continue

        LOGGER.info("Recipients for ASN %s: %s", asn, ", ".join(recipients) or "<none>")
        if recipient_asns is not None:
            LOGGER.debug("Additional ASN data from digest for %s: %s", asn, recipient_asns)

        if args.debug:
            recipients = [args.debug_recipient]

        if not recipients:
            LOGGER.warning("Skipping ASN %s because no recipients were found", asn)
            continue

        detail_text = build_detail_text(headerline, rows_for_asn)
        body = template.substitute({"details": detail_text})

        try:
            create_ticket_for_asn(
                tracker=tracker,
                incident_id=args.incident_id,
                queue_id=DEFAULT_QUEUE_ID,
                asn=asn,
                recipients=recipients,
                subject_prefix=subject_prefix,
                body=body,
                dry_run=args.dry_run,
            )
        except rt.RtError as exc:
            LOGGER.error("RT operation failed for ASN %s: %s", asn, exc)
            continue

        if args.debug:
            LOGGER.info("Debug mode enabled, stopping after first ticket")
            break

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        LOGGER.error(exc)
        raise SystemExit(1)


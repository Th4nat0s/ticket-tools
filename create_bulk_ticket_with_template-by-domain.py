#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import sys
import time
import re
import subprocess
from collections import defaultdict
from string import Template
from typing import Dict, List, Optional, Sequence, Set, Tuple
from rt.exceptions import APISyntaxError

import rt
from pyurlabuse import PyURLAbuse
import config as cfg

LOGGER = logging.getLogger(__name__)
DEFAULT_QUEUE_ID = 5
PYURLABUSE_RETRY_DELAY = 5
EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LU_WHOIS_HOST = "whois.dns.lu"
LU_WHOIS_PORT = "4300"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create one RT ticket per domain from a CSV file")
    parser.add_argument("incident_id")
    parser.add_argument("template_name")
    parser.add_argument("csv_file")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--debug-recipient", default="sascha@rommelfangen.de")
    return parser.parse_args()


def setup_logging():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def resolve_template_path(template_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), template_name)


def create_tracker() -> rt.Rt:
    tracker = rt.Rt(cfg.rt_url, cfg.rt_user, cfg.rt_pass, verify_cert=False)
    tracker.login()
    return tracker


def load_template(path: str):
    with open(path, "r", encoding="utf-8") as f:
        subject = f.readline().rstrip()
        return subject, Template(f.read())


def load_csv_rows(path: str):
    with open(path, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    if not rows:
        raise RuntimeError("CSV file is empty")

    header_row = rows[0]
    if not header_row:
        raise RuntimeError("CSV header is empty")

    first_col = header_row[0].strip().lower()

    if first_col not in ("domain", "ip", "asn"):
        raise RuntimeError(
            f"Invalid CSV header: first column must be 'domain', 'ip' or 'asn', got '{header_row[0]}'"
        )

    header = ",".join(header_row)
    data_rows = rows[1:]

    return header, data_rows


def extract_emails(text: str) -> List[str]:
        return list({normalize_email(e) for e in EMAIL_REGEX.findall(text or "")})


def normalize_email(email: str) -> str:
        return email.strip().lower().rstrip(".,;:<>")


def extract_emails_from_rows(rows):
    emails = set()
    for row in rows:
        for v in row:
            emails.update(extract_emails(v))
    return list(emails)


def query_lu_whois(domain: str) -> List[str]:
    if not domain.endswith(".lu"):
        return []
    try:
        result = subprocess.run(
            ["whois", "-h", LU_WHOIS_HOST, "-p", LU_WHOIS_PORT, domain],
            capture_output=True,
            text=True,
            timeout=10
        )
    except Exception as e:
        LOGGER.warning("WHOIS failed for %s: %s", domain, e)
        return []

    parts = []
    if result.stdout:
        parts.append(result.stdout)
    if result.stderr:
        parts.append(result.stderr)

    output = "\n".join(parts)
    return extract_emails(output)


def group_rows(rows, exclude):
    grouped = defaultdict(list)
    exclude = {x.lower() for x in exclude}

    for row in rows:
        if not row:
            continue

        domain = row[0].strip().lower()
        if not domain or domain in exclude:
            continue

        grouped[domain].append(row)

    return grouped


def lookup_recipients(domain, rows):
    emails = set()

    # PyURLAbuse
    try:
        p = PyURLAbuse()
        r = p.run_query(domain, with_digest=True)
        time.sleep(PYURLABUSE_RETRY_DELAY)
        r = p.run_query(domain, with_digest=True)

        if "digest" in r and len(r["digest"]) > 1:
            for e in r["digest"][1]:
                emails.add(normalize_email("".join(e)))
    except Exception as e:
        LOGGER.warning("PyURLAbuse failed for %s: %s", domain, e)

    # CSV emails
    emails.update(extract_emails_from_rows(rows))

    # LU whois
    emails.update(query_lu_whois(domain))

    return sorted({normalize_email(e) for e in emails if e})


def build_text(header, rows):
    lines = []
    if header:
        lines.append(" " + header)
    lines.extend([" " + ",".join(r) for r in rows])
    return "\n".join(lines)


def create_ticket(tracker, incident, domain, recipients, subject_prefix, body, dry):
    subject = f"{subject_prefix} ({domain})"

    if dry:
        LOGGER.info("DRY-RUN domain=%s recipients=%s", domain, ",".join(recipients))
        LOGGER.info("DRY-RUN subject=%s", subject)
        LOGGER.info("DRY-RUN body=\n%s", body)
        return

    LOGGER.info("Creating ticket for domain=%s", domain)
    LOGGER.info("Recipients: %s", ", ".join(recipients))

    tid = None

    try:
        tid = tracker.create_ticket(
            Queue=str(DEFAULT_QUEUE_ID),
            Subject=subject,
            Text=body,
            Requestors=", ".join(recipients)
        )
        LOGGER.info("Ticket created: %s", tid)
    except APISyntaxError as e:
        msg = str(e)
        match = re.search(r"Ticket\s+(\d+)\s+created", msg, re.IGNORECASE)
        if match:
            tid = match.group(1)
            LOGGER.warning(
                "RT returned APISyntaxError although ticket %s was created for domain %s",
                tid,
                domain,
            )
        else:
            raise

    if not tid:
        raise RuntimeError(f"Could not determine ticket id for domain {domain}")

    LOGGER.info("Sending correspondence for ticket %s", tid)
    tracker.reply(tid, text=body)

    LOGGER.info("Linking ticket %s to incident %s", tid, incident)
    tracker.edit_ticket_links(tid, MemberOf=str(incident))

    LOGGER.info("Finished ticket %s for domain %s", tid, domain)


def main():
    setup_logging()
    args = parse_args()

    subject, template = load_template(resolve_template_path(args.template_name))
    header, rows = load_csv_rows(args.csv_file)
    grouped = group_rows(rows, cfg.known_good_excludelist)

    tracker = create_tracker()

    LOGGER.info("Starting processing of %d domains", len(grouped))

    total_domains = len(grouped)
    for index, (domain, rows_for_domain) in enumerate(grouped.items(), start=1):
        LOGGER.info("[%d/%d] Processing domain: %s", index, total_domains, domain)
        recips = lookup_recipients(domain, rows_for_domain)

        if args.debug:
            recips = [args.debug_recipient]

        if not recips:
            LOGGER.warning("No recipients found for domain %s — skipping", domain)
            continue

        body = template.substitute({"details": build_text(header, rows_for_domain)})

        create_ticket(tracker, args.incident_id, domain, recips, subject, body, args.dry_run)

        if args.debug:
            break


if __name__ == "__main__":
    main()


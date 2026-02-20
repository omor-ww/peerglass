"""
normalizer.py — Normalize raw RDAP responses into unified data models.

Each RIR returns RDAP JSON that is almost the same but with subtle
differences in field names, nesting depth, and vCard (jCard) structure.

This module is the "translation layer" — like a universal adapter plug
that lets you connect appliances from 5 different countries to a single
power socket. You plug in any RIR's response and get a clean, consistent
object out.

Key RDAP quirks handled here:
  - jCard (RFC 7095) vcard arrays for contact information
  - Nested entity hierarchies for org / abuse contacts
  - cidr0_cidrs extension (APNIC, RIPE) vs startAddress/endAddress (ARIN)
  - Country codes at different nesting levels
  - Events array for registration / last-changed dates
"""

from __future__ import annotations
from typing import Any, Optional
from models import NetworkResource, ASNResource, AbuseContact


# ──────────────────────────────────────────────────────────────
# jCard / vCard helpers
# ──────────────────────────────────────────────────────────────

def _vcard_field(vcard_array: list, field_name: str) -> Optional[str]:
    """
    Extract a named field from a jCard array.

    jCard looks like:
      [["version",{},"text","4.0"], ["fn",{},"text","ACME Corp"], ...]

    We find the entry whose first element matches field_name and return
    the 4th element (the actual value).
    """
    if not vcard_array:
        return None
    for entry in vcard_array:
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == field_name:
            return str(entry[3]) if entry[3] else None
    return None


def _walk_entities_for_email(entities: list, target_roles: set[str]) -> Optional[str]:
    """
    Walk the RDAP entity tree looking for an email in an entity
    whose role matches one of the target_roles.
    """
    if not entities:
        return None
    for entity in entities:
        roles = set(entity.get("roles", []))
        if roles & target_roles:
            vcard = entity.get("vcardArray", [None, []])[1]
            email = _vcard_field(vcard, "email")
            if email:
                return email
        # Recurse into nested entities
        nested_email = _walk_entities_for_email(entity.get("entities", []), target_roles)
        if nested_email:
            return nested_email
    return None


def _walk_entities_for_contacts(
    entities: list,
    target_roles: set[str],
    emails: list[str],
    phones: list[str],
) -> None:
    """Collect all emails and phones from matching entities (in-place)."""
    for entity in entities:
        roles = set(entity.get("roles", []))
        if roles & target_roles:
            vcard = entity.get("vcardArray", [None, []])[1]
            email = _vcard_field(vcard, "email")
            phone = _vcard_field(vcard, "tel")
            if email and email not in emails:
                emails.append(email)
            if phone and phone not in phones:
                phones.append(phone)
        _walk_entities_for_contacts(entity.get("entities", []), target_roles, emails, phones)


def _org_name_from_entities(entities: list) -> Optional[str]:
    """Find the registrant / administrative entity's full name."""
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrant" in roles or "administrative" in roles:
            vcard = entity.get("vcardArray", [None, []])[1]
            fn = _vcard_field(vcard, "fn")
            if fn:
                return fn
    return None


def _abuse_email_from_remarks(remarks: list) -> Optional[str]:
    """Fallback: extract an email-like token from RDAP remarks (used by LACNIC)."""
    for remark in (remarks or []):
        for line in remark.get("description", []):
            if "abuse" in line.lower() and "@" in line:
                for token in line.split():
                    cleaned = token.strip(",;:<>")
                    if "@" in cleaned and "." in cleaned:
                        return cleaned
    return None


def _parse_events(events: list) -> dict[str, Optional[str]]:
    """Return registration and last-changed dates from the RDAP events array."""
    dates: dict[str, Optional[str]] = {"registration": None, "last_changed": None}
    for event in (events or []):
        action = event.get("eventAction", "").lower().replace(" ", "_")
        date   = event.get("eventDate", "")
        if action == "registration":
            dates["registration"] = date
        elif action in ("last_changed", "expiration", "reregistration"):
            dates["last_changed"] = date
    return dates


def _country_from_rdap(rdap: dict) -> Optional[str]:
    """Country code lives at top-level or buried in entity vCard ADR fields."""
    top_level = rdap.get("country")
    if top_level:
        return str(top_level).upper()
    # Try entity vCards (ADR field — last element is country)
    for entity in rdap.get("entities", []):
        vcard = entity.get("vcardArray", [None, []])[1]
        adr = _vcard_field(vcard, "adr")
        if isinstance(adr, list) and len(adr) > 6 and adr[6]:
            return str(adr[6]).upper()
    return None


def _prefix_from_rdap(rdap: dict) -> Optional[str]:
    """
    Extract the CIDR prefix string.
    APNIC/RIPE use the cidr0_cidrs extension.
    ARIN uses startAddress / endAddress without a built-in prefix.
    """
    cidr_list = rdap.get("cidr0_cidrs", [])
    if cidr_list:
        first = cidr_list[0]
        network = first.get("v4prefix") or first.get("v6prefix", "")
        length  = first.get("length", "")
        if network and length:
            return f"{network}/{length}"

    # Direct prefix field (some RIRs)
    if rdap.get("prefix"):
        return rdap["prefix"]

    # Fallback to start-end range notation
    start = rdap.get("startAddress", "")
    end   = rdap.get("endAddress", "")
    if start and end:
        return f"{start} – {end}"

    return None


def _ip_version(rdap: dict) -> Optional[int]:
    raw = rdap.get("ipVersion", "")
    if raw in ("v4", "4"):
        return 4
    if raw in ("v6", "6"):
        return 6
    return None


def _status_string(rdap: dict) -> Optional[str]:
    status = rdap.get("status")
    if isinstance(status, list):
        return status[0] if status else None
    return status


# ──────────────────────────────────────────────────────────────
# Public normalizers
# ──────────────────────────────────────────────────────────────

def normalize_ip_response(rir: str, rdap: dict) -> NetworkResource:
    """Convert any RIR's RDAP /ip/{address} response to a NetworkResource."""
    events   = _parse_events(rdap.get("events", []))
    entities = rdap.get("entities", [])

    abuse_email = _walk_entities_for_email(entities, {"abuse", "technical", "noc"})
    if not abuse_email:
        abuse_email = _walk_entities_for_email(entities, {"registrant", "administrative"})
    if not abuse_email:
        abuse_email = _abuse_email_from_remarks(rdap.get("remarks", []))

    return NetworkResource(
        rir             = rir,
        prefix          = _prefix_from_rdap(rdap),
        handle          = rdap.get("handle"),
        name            = rdap.get("name"),
        org_name        = _org_name_from_entities(entities),
        country         = _country_from_rdap(rdap),
        allocation_date = events["registration"],
        last_changed    = events["last_changed"],
        abuse_email     = abuse_email,
        status          = _status_string(rdap),
        ip_version      = _ip_version(rdap),
        raw             = rdap,
    )


def normalize_asn_response(rir: str, rdap: dict) -> ASNResource:
    """Convert any RIR's RDAP /autnum/{asn} response to an ASNResource."""
    events   = _parse_events(rdap.get("events", []))
    entities = rdap.get("entities", [])

    asn_start = rdap.get("startAutnum")
    asn_end   = rdap.get("endAutnum")
    if asn_start is not None:
        asn_str = f"AS{asn_start}" if asn_start == asn_end else f"AS{asn_start}–AS{asn_end}"
    else:
        asn_str = rdap.get("handle", "")

    abuse_email = _walk_entities_for_email(entities, {"abuse", "technical", "noc"})
    if not abuse_email:
        abuse_email = _walk_entities_for_email(entities, {"registrant", "administrative"})

    return ASNResource(
        rir             = rir,
        asn             = asn_str,
        name            = rdap.get("name"),
        org_name        = _org_name_from_entities(entities),
        country         = _country_from_rdap(rdap),
        allocation_date = events["registration"],
        last_changed    = events["last_changed"],
        abuse_email     = abuse_email,
        status          = _status_string(rdap),
        raw             = rdap,
    )


def extract_abuse_contact(rir: str, ip: str, rdap: dict) -> AbuseContact:
    """Extract structured abuse contact information from an RDAP response."""
    entities = rdap.get("entities", [])
    emails: list[str] = []
    phones: list[str] = []

    _walk_entities_for_contacts(entities, {"abuse", "technical", "noc"}, emails, phones)

    if not emails:
        fallback = _abuse_email_from_remarks(rdap.get("remarks", []))
        if fallback:
            emails.append(fallback)

    org_name = _org_name_from_entities(entities)

    return AbuseContact(
        ip_address        = ip,
        authoritative_rir = rir,
        abuse_email       = emails,
        abuse_phone       = phones,
        network_name      = rdap.get("name"),
        network_handle    = rdap.get("handle"),
        org_name          = org_name,
        country           = _country_from_rdap(rdap),
        raw               = rdap,
    )

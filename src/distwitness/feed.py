"""Deterministic Atom feed generation using the standard XML library."""

from __future__ import annotations

from datetime import UTC, datetime
from xml.etree import ElementTree as ET

from distwitness.models import ChangeEvent

ATOM = "http://www.w3.org/2005/Atom"
SITE_URL = "https://slicedearth.github.io/distwitness/"

ET.register_namespace("", ATOM)


def build_atom_feed(
    events: tuple[ChangeEvent, ...],
    *,
    title: str,
    updated_at: datetime | None,
) -> str:
    """Build valid, ordered Atom XML containing compact original explanations."""

    root = ET.Element(f"{{{ATOM}}}feed")
    ET.SubElement(
        root, f"{{{ATOM}}}id"
    ).text = "https://github.com/slicedearth/distwitness"
    ET.SubElement(root, f"{{{ATOM}}}title").text = f"{title} change feed"
    ET.SubElement(
        root,
        f"{{{ATOM}}}link",
        {"href": SITE_URL, "rel": "alternate", "type": "text/html"},
    )
    ET.SubElement(
        root,
        f"{{{ATOM}}}link",
        {"href": f"{SITE_URL}feed.xml", "rel": "self", "type": "application/atom+xml"},
    )
    resolved_updated = updated_at or datetime(1970, 1, 1, tzinfo=UTC)
    ET.SubElement(root, f"{{{ATOM}}}updated").text = _atom_time(resolved_updated)
    author = ET.SubElement(root, f"{{{ATOM}}}author")
    ET.SubElement(author, f"{{{ATOM}}}name").text = "DistWitness"

    for event in sorted(
        events, key=lambda item: (item.detected_at, item.id), reverse=True
    ):
        entry = ET.SubElement(root, f"{{{ATOM}}}entry")
        ET.SubElement(entry, f"{{{ATOM}}}id").text = f"urn:distwitness:event:{event.id}"
        ET.SubElement(
            entry, f"{{{ATOM}}}title"
        ).text = f"{event.package_name}: {event.event_type.replace('_', ' ')}"
        ET.SubElement(entry, f"{{{ATOM}}}updated").text = _atom_time(event.detected_at)
        ET.SubElement(entry, f"{{{ATOM}}}published").text = _atom_time(
            event.detected_at
        )
        link = event.source_links[0] if event.source_links else SITE_URL
        ET.SubElement(
            entry,
            f"{{{ATOM}}}link",
            {"href": link, "rel": "alternate"},
        )
        ET.SubElement(entry, f"{{{ATOM}}}category", {"term": event.event_type})
        ET.SubElement(
            entry,
            f"{{{ATOM}}}category",
            {"term": event.review_priority.value},
        )
        ET.SubElement(
            entry, f"{{{ATOM}}}summary", {"type": "text"}
        ).text = event.explanation
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def _atom_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

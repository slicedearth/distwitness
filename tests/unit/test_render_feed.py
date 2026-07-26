from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from distwitness.compare import compare_snapshots
from distwitness.config import load_config
from distwitness.feed import build_atom_feed
from distwitness.models import (
    PackageConfig,
    ProjectConfig,
    SourceHealthObservation,
    SourceName,
    StateDocument,
)
from distwitness.render import (
    EVENTS_PER_PAGE,
    MANIFEST,
    build_site,
    get_pagination_items,
)
from tests.factories import NOW, release_file, snapshot, source_error


def _health_history() -> tuple[SourceHealthObservation, ...]:
    sources: tuple[SourceName, ...] = ("pypi", "pypi_integrity", "osv")
    return tuple(
        SourceHealthObservation(
            source=source,
            observed_at=NOW,
            status="available",
            checked_packages=1,
            successful_packages=1,
            error_count=0,
            retryable_error_count=0,
        )
        for source in sources
    )


def _state_with_event(*, malicious: bool = False) -> StateDocument:
    old = snapshot()
    display_name = "<script>alert('x')</script>" if malicious else "Demo"
    changed_file = release_file(
        filename="<script>-demo-1.1.0-py3-none-any.whl"
        if malicious
        else ("demo-1.1.0-py3-none-any.whl")
    )
    new = snapshot(
        version="1.1.0",
        files=(changed_file,),
        display_name=display_name,
        source_errors=(source_error(source="pypi_integrity"),) if malicious else (),
    )
    events = compare_snapshots(
        old,
        new,
        package_config=PackageConfig(name="demo"),
        project_config=ProjectConfig(title="DistWitness"),
        detected_at=NOW,
    )
    return StateDocument(
        snapshots={"demo": new},
        events=events,
        source_health_history=_health_history(),
        last_successful_run=NOW,
    )


def _state_with_events(count: int) -> StateDocument:
    state = _state_with_event()
    event = state.events[0]
    events = tuple(
        event.model_copy(
            update={
                "id": f"{index + 1:064x}",
                "detected_at": NOW - timedelta(minutes=index),
                "explanation": f"Change event {index + 1}.",
            }
        )
        for index in range(count)
    )
    return state.model_copy(update={"events": events})


def test_static_build_outputs_all_formats_and_valid_xml(tmp_path: Path) -> None:
    config = load_config(Path("config/watchlist.yml"))
    written = build_site(_state_with_event(), config, output_dir=tmp_path)
    assert tmp_path / "index.html" in written
    assert (tmp_path / "packages/demo.html").exists()
    assert (tmp_path / "feed.xml").exists()
    assert (tmp_path / "assets/logo.svg").exists()
    ET.parse(tmp_path / "feed.xml")  # noqa: S314 - locally generated XML.
    current = json.loads((tmp_path / "data/current.json").read_text())
    events = json.loads((tmp_path / "data/events.json").read_text())
    health = json.loads((tmp_path / "data/health.json").read_text())
    assert current["schema_version"] == 3
    assert current["packages"][0]["schema_version"] == 2
    assert current["packages"][0]["release_discovery"] == "pypi-index-v1"
    assert current["source_health"]["pypi"]["observed_runs"] == 1
    assert events["events"]
    assert events["schema_version"] == 1
    assert health["schema_version"] == 1
    assert len(health["observations"]) == 3
    assert "source_errors" not in current["packages"][0]
    package_html = (tmp_path / "packages/demo.html").read_text(encoding="utf-8")
    assert "PyPI Index API v1.4" in package_html
    index_html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "1 of 1 retained run observations complete" in index_html
    assert 'href="data/health.json"' in index_html
    assert (tmp_path / "reports/latest.md").read_text().startswith("# DistWitness")


def test_pagination_items_preserve_nearby_context() -> None:
    assert get_pagination_items(1, 200) == (1, 2, 3, 4, 5, 6, None, 200)
    assert get_pagination_items(100, 200) == (
        1,
        None,
        98,
        99,
        100,
        101,
        102,
        None,
        200,
    )
    assert get_pagination_items(200, 200, 1) == (1, None, 197, 198, 199, 200)
    assert get_pagination_items(2, 5) == (1, 2, 3, 4, 5)


def test_pagination_rejects_invalid_contracts() -> None:
    for arguments in ((0, 1, 2), (2, 1, 2), (1, 0, 2), (1, 2, -1)):
        with pytest.raises(ValueError):
            get_pagination_items(*arguments)


def test_source_health_becomes_measured_only_after_seven_observations(
    tmp_path: Path,
) -> None:
    history = tuple(
        observation.model_copy(update={"observed_at": NOW - timedelta(days=day)})
        for day in range(7)
        for observation in _health_history()
    )
    state = _state_with_event().model_copy(update={"source_health_history": history})

    build_site(
        state,
        load_config(Path("config/watchlist.yml")),
        output_dir=tmp_path,
    )

    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    health = json.loads((tmp_path / "data/health.json").read_text())
    assert "7 of 7 retained run observations complete" in html
    assert "measured history" in html
    assert len(health["observations"]) == 21


def test_static_change_pages_have_responsive_navigation_and_cleanup(
    tmp_path: Path,
) -> None:
    config = load_config(Path("config/watchlist.yml"))
    state = _state_with_events(EVENTS_PER_PAGE * 2 + 5)

    build_site(state, config, output_dir=tmp_path)

    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    page_two = (tmp_path / "changes/page-2.html").read_text(encoding="utf-8")
    page_three = (tmp_path / "changes/page-3.html").read_text(encoding="utf-8")
    assert "Showing 1-20 of 45 retained changes." in index
    assert "Change event 1." in index
    assert "Change event 21." not in index
    assert 'href="changes/page-2.html#changes"' in index
    assert "Showing 21-40 of 45 retained changes." in page_two
    assert "Change event 21." in page_two
    assert 'href="../index.html#changes"' in page_two
    assert 'href="page-3.html#changes"' in page_two
    assert "Page 2 of 3" in page_two
    assert 'class="pagination__pages pagination__pages--desktop"' in page_two
    assert 'class="pagination__pages pagination__pages--mobile"' in page_two
    assert 'aria-current="page"' in page_two
    assert 'src="../assets/logo.svg"' in page_two
    assert "Showing 41-45 of 45 retained changes." in page_three
    assert "Change event 45." in page_three

    build_site(_state_with_events(1), config, output_dir=tmp_path)
    assert not (tmp_path / "changes/page-2.html").exists()
    assert not (tmp_path / "changes").exists()


def test_html_and_xml_escape_untrusted_metadata(tmp_path: Path) -> None:
    config = load_config(Path("config/watchlist.yml"))
    state = _state_with_event(malicious=True)
    build_site(state, config, output_dir=tmp_path)
    html = (tmp_path / "packages/demo.html").read_text(encoding="utf-8")
    atom = (tmp_path / "feed.xml").read_text(encoding="utf-8")
    assert "<script>alert('x')</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<script>-demo" not in html
    ET.fromstring(atom)  # noqa: S314 - locally generated XML.


def test_assets_have_no_remote_requests_or_inner_html(tmp_path: Path) -> None:
    build_site(
        StateDocument(), load_config(Path("config/watchlist.yml")), output_dir=tmp_path
    )
    script = (tmp_path / "assets/app.js").read_text(encoding="utf-8")
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "innerHTML" not in script
    assert "fetch(" not in script
    assert "connect-src 'none'" in html
    assert "https://" not in script


def test_manifest_only_removes_previously_generated_stale_files(tmp_path: Path) -> None:
    config = load_config(Path("config/watchlist.yml"))
    state = _state_with_event()
    build_site(state, config, output_dir=tmp_path)
    unrelated = tmp_path / "operator-note.txt"
    unrelated.write_text("keep", encoding="utf-8")
    manifest_path = tmp_path / MANIFEST
    manifest = json.loads(manifest_path.read_text())
    manifest.append("packages/stale.html")
    (tmp_path / "packages/stale.html").write_text("stale", encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    build_site(StateDocument(), config, output_dir=tmp_path)
    assert not (tmp_path / "packages/stale.html").exists()
    assert unrelated.read_text() == "keep"


def test_atom_order_and_ids_are_stable() -> None:
    state = _state_with_event()
    first = build_atom_feed(state.events, title="Test", updated_at=NOW)
    second = build_atom_feed(
        tuple(reversed(state.events)), title="Test", updated_at=NOW
    )
    assert first == second
    assert "urn:distwitness:event:" in first
    ET.fromstring(first)  # noqa: S314 - locally generated XML.

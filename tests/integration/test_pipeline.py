from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import httpx

from distwitness.config import load_config
from distwitness.http import BoundedHttpClient
from distwitness.models import StateDocument
from distwitness.runner import (
    build_source_health_observations,
    collect,
    prepare_run,
)
from distwitness.storage import load_state
from tests.factories import NOW, pypi_index, pypi_project, snapshot, vulnerability


def _config(path: Path, *, name: str = "demo") -> Path:
    path.write_text(
        (
            "project:\n"
            "  title: DistWitness Test\n"
            "  retention_days: 30\n"
            "  max_packages: 1\n"
            "packages:\n"
            f"  - name: {name}\n"
        ),
        encoding="utf-8",
    )
    return path


def _http(
    project_data: dict[str, object], *, osv_status: int = 200
) -> BoundedHttpClient:
    info = project_data["info"]
    urls = project_data["urls"]
    assert isinstance(info, dict)
    assert isinstance(urls, list) and urls
    first_file = urls[0]
    assert isinstance(first_file, dict)
    display_name = str(info["name"])
    version = str(info["version"])
    filename = str(first_file["filename"])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "pypi.org":
            if request.url.path.startswith("/simple/"):
                return httpx.Response(
                    200,
                    json=pypi_index(
                        name=display_name.casefold(),
                        version=version,
                        filename=filename,
                    ),
                )
            if request.url.path.startswith("/integrity/"):
                return httpx.Response(404)
            return httpx.Response(200, json=project_data)
        if request.url.path == "/v1/querybatch":
            if osv_status != 200:
                return httpx.Response(osv_status)
            return httpx.Response(200, json={"results": [{"vulns": []}]})
        raise AssertionError(f"unexpected request: {request.url}")

    return BoundedHttpClient(
        user_agent="DistWitness tests (+https://example.test)",
        max_retries=0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _delay: None,
        jitter=lambda _start, _end: 0,
    )


def test_baseline_change_and_repeat_run_are_deterministic(tmp_path: Path) -> None:
    config = _config(tmp_path / "watchlist.yml")
    state_dir = tmp_path / "state"
    output_dir = tmp_path / "site"
    first = prepare_run(
        config_path=config,
        state_dir=state_dir,
        output_dir=output_dir,
        dry_run=False,
        no_cache=False,
        now=NOW,
        http=_http(pypi_project()),
    )
    assert first.result.events_created == 0
    assert len(first.state.source_health_history) == 3
    assert all(
        observation.status == "available"
        for observation in first.state.source_health_history
    )
    assert (output_dir / "index.html").exists()
    assert load_state(state_dir).events == ()

    changed_data = pypi_project(
        version="1.1.0",
        filename="demo-1.1.0-py3-none-any.whl",
    )
    second = prepare_run(
        config_path=config,
        state_dir=state_dir,
        output_dir=output_dir,
        dry_run=False,
        no_cache=False,
        now=NOW + timedelta(days=1),
        http=_http(changed_data),
    )
    assert second.result.events_created == 1
    retained = load_state(state_dir).events
    assert any(event.event_type == "new_release" for event in retained)

    third = prepare_run(
        config_path=config,
        state_dir=state_dir,
        output_dir=output_dir,
        dry_run=False,
        no_cache=False,
        now=NOW + timedelta(days=2),
        http=_http(changed_data),
    )
    assert third.result.events_created == 0
    assert [event.id for event in load_state(state_dir).events] == [
        event.id for event in retained
    ]
    assert len(third.state.source_health_history) == 9


def test_v1_state_migrates_and_refreshes_without_a_false_event(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path / "watchlist.yml")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    legacy = StateDocument(
        snapshots={
            "demo": snapshot(
                project_urls={"Source": "https://example.test/demo"},
            )
        }
    ).model_dump(mode="json")
    legacy["schema_version"] = 1
    legacy.pop("source_health_history")
    legacy_snapshot = legacy["snapshots"]["demo"]
    legacy_snapshot["schema_version"] = 1
    legacy_snapshot.pop("release_discovery")
    legacy_snapshot.pop("index_api_version")
    (state_dir / "state.json").write_text(
        json.dumps(legacy, sort_keys=True),
        encoding="utf-8",
    )

    outcome = prepare_run(
        config_path=config,
        state_dir=state_dir,
        output_dir=tmp_path / "site",
        dry_run=False,
        no_cache=False,
        now=NOW,
        http=_http(pypi_project()),
    )

    persisted = load_state(state_dir)
    assert outcome.result.events_created == 0
    assert persisted.schema_version == 3
    assert persisted.snapshots["demo"].release_discovery == "pypi-index-v1"
    assert persisted.snapshots["demo"].index_api_version == "1.4"
    assert len(persisted.source_health_history) == 3


def test_incomplete_osv_preserves_exact_version_advisories(tmp_path: Path) -> None:
    config_path = _config(tmp_path / "watchlist.yml")
    config = load_config(config_path)
    previous_snapshot = snapshot(vulnerabilities=(vulnerability(),))
    result = collect(
        config,
        previous=StateDocument(snapshots={"demo": previous_snapshot}),
        now=NOW,
        http=_http(pypi_project(), osv_status=503),
    )
    assert result.snapshots["demo"].vulnerabilities == previous_snapshot.vulnerabilities
    assert any(error.source == "osv" for error in result.source_errors)
    observations = build_source_health_observations(
        config,
        result,
        observed_at=NOW,
    )
    osv_health = next(item for item in observations if item.source == "osv")
    assert osv_health.status == "partial"
    assert osv_health.checked_packages == 1
    assert osv_health.successful_packages == 0


def test_dry_run_writes_no_state_or_output(tmp_path: Path) -> None:
    outcome = prepare_run(
        config_path=_config(tmp_path / "watchlist.yml"),
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "site",
        dry_run=True,
        no_cache=True,
        now=NOW,
        http=_http(pypi_project()),
    )
    assert outcome.result.dry_run is True
    assert not (tmp_path / "state/state.json").exists()
    assert not (tmp_path / "site").exists()


def test_removed_watchlist_package_leaves_current_state_and_output(
    tmp_path: Path,
) -> None:
    config_path = _config(tmp_path / "watchlist.yml")
    state_dir = tmp_path / "state"
    output_dir = tmp_path / "site"
    prepare_run(
        config_path=config_path,
        state_dir=state_dir,
        output_dir=output_dir,
        dry_run=False,
        no_cache=False,
        now=NOW,
        http=_http(pypi_project()),
    )
    assert (output_dir / "packages/demo.html").exists()

    _config(config_path, name="replacement")
    replacement_data = pypi_project(
        name="Replacement",
        filename="replacement-1.0.0-py3-none-any.whl",
    )
    prepare_run(
        config_path=config_path,
        state_dir=state_dir,
        output_dir=output_dir,
        dry_run=False,
        no_cache=False,
        now=NOW + timedelta(days=1),
        http=_http(replacement_data),
    )
    current = load_state(state_dir)
    assert tuple(current.snapshots) == ("replacement",)
    assert not (output_dir / "packages/demo.html").exists()
    assert (output_dir / "packages/replacement.html").exists()


def test_total_collection_failure_is_operational_and_preserves_state(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path / "watchlist.yml")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    http = BoundedHttpClient(
        user_agent="DistWitness tests (+https://example.test)",
        max_retries=0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    outcome = prepare_run(
        config_path=config,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "site",
        dry_run=False,
        no_cache=False,
        now=NOW,
        http=http,
    )
    assert outcome.operational_failure is True
    assert not (tmp_path / "state/state.json").exists()
    assert not (tmp_path / "site").exists()

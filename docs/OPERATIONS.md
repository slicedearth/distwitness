# Operations

## Routine scheduled operation

The provided workflow runs daily at a non-round UTC minute and can also be
started with `workflow_dispatch`. It reads trusted default-branch code, recovers
compact prior state from a workflow cache when available, performs the live
run, uploads generated output between jobs, and updates `gh-pages` only when
public site content changes. The state file is never copied to the generated
branch or Pages payload.

Normal findings do not fail the run. An inability to collect any configured
package, invalid configuration/state, or output failure is operational and
returns non-zero.

## Manual local run

```bash
. .venv/bin/activate
python -m distwitness doctor
python -m distwitness validate
python -m distwitness run --dry-run
python -m distwitness run
```

Use `scan` when a normalised live preview is needed without persistence. Use
`build` to regenerate output from saved state with no network access.

## API failures and stale data

- PyPI failure: preserve the package's prior snapshot and record the failed
  attempt.
- Integrity 404: record `absent`; 403: record `unavailable`; transport failure:
  record `request_failed`.
- OSV incomplete/failure: preserve applicable exact-version advisories and
  suppress advisory-removal comparisons.

The dashboard visibly reports partial/degraded health and last complete run.
Do not delete findings merely to make a source appear healthy.

Persisted runs also append one aggregate observation for PyPI, PyPI Integrity,
and OSV. The dashboard and `data/health.json` report exact retained run and
package-check counts. Fewer than seven observations are a baseline, not a
reliability claim. A package check without a recorded source error does not
prove that upstream data was complete or correct.

For 429 or 5xx responses, allow the bounded retry policy to finish. Avoid rapid
manual reruns. If an upstream schema changed, disable scheduled publication by
disabling the workflow in GitHub, repair the adapter with fixtures, and
revalidate before resuming.

## State corruption and recovery

DistWitness preserves malformed `state/state.json` and exits. Do not edit or
delete it reflexively.

State v1 and v2 are migrated to v3 in memory during load. The original file is
not rewritten merely by validation; the next successful non-dry run persists
v3 and begins real source-health history. Historical package snapshots are
labelled `legacy-project-json` until a successful collection replaces them with
Index API observations. Unknown schema versions still fail closed. See
[`STATE_SCHEMA.md`](STATE_SCHEMA.md).

1. Copy the problematic file outside the state directory for investigation.
2. Validate a known-good prior state copy:
   `python -m distwitness validate --state-dir <recovered-directory>`.
3. Restore the known-good `state.json`.
4. Run `--dry-run`, inspect the summary, then run normally.

If no trustworthy state exists, move the corrupt file aside deliberately and
allow the next successful run to establish a new baseline. Document that
history continuity was lost; the baseline produces no synthetic events.

## Workflow state-cache recovery

The workflow cache is operational continuity, not a backup or confidentiality
boundary. It contains only the compact state documented in
[`STATE_SCHEMA.md`](STATE_SCHEMA.md), but workflow code that can restore the
default-branch cache can read it. Never add credentials, private package names,
raw responses, or operator data to persisted state.

1. Disable the scheduled workflow to prevent concurrent publication.
2. List repository caches whose keys begin with `distwitness-state-`.
3. If the newest cache is corrupt, delete that exact entry so the next run can
   restore the preceding cache. Delete every matching cache only when a
   deliberate new baseline is required.
4. Manually dispatch the workflow and inspect the collection summary.
5. Confirm `gh-pages` contains only generated site files, `.nojekyll`, public
   JSON, and reports. It must not contain `.distwitness-state` or `state.json`.
6. Re-enable the schedule after the result is validated.

GitHub may evict caches. If no cache is available, the next successful run
establishes a new baseline without synthetic events. Record the continuity
break. Never copy source, `.github/workflows`, secrets, caches, state files, raw
responses, or package archives to `gh-pages`.

## Retention and state rotation

Events older than `retention_days` are pruned during a successful run. Current
snapshots remain as the comparison baseline.

To rotate all generated state:

1. Disable the schedule.
2. Archive the old state privately if policy requires.
3. Delete only the repository caches whose keys begin with
   `distwitness-state-`.
4. Run once to establish a fresh baseline.
5. Verify no synthetic change events were created.
6. Publish and re-enable the schedule.

This is a discontinuity, not an ordinary repair; record the rotation date.

## Source removal or correction

Remove a package from `config/watchlist.yml` through a reviewed source change.
The current MVP does not automatically erase its historical events; they age
out under retention. For an urgent correction, perform a documented state
rotation or prepare a narrowly reviewed state migration.

Default-list inclusion and exclusion criteria are in
[`WATCHLIST_POLICY.md`](WATCHLIST_POLICY.md). Expanding the list must retain
sequential collection, the configured package limit, and enough workflow time
for bounded retries to finish.

Upstream factual corrections should be made at PyPI or the authoritative
advisory database. DistWitness should link to, not overwrite, upstream records.

## Pages enablement

After the first generated branch exists, set repository Pages to **Deploy from a
branch**, `gh-pages`, `/ (root)`. This is a manual repository setting. Confirm
the final Pages URL before adding any “live” claim to public documentation.

Forks do not run schedules by default. Fork owners must explicitly enable
Actions, choose their own Pages settings, and understand that the watchlist and
findings become public.

GitHub may disable scheduled workflows after repository inactivity. Re-enable
the workflow in the Actions tab and run a manual dispatch to validate state and
permissions.

## Incident response

For suspected generated-site or workflow compromise:

1. Disable the scheduled workflow and Pages.
2. Preserve the relevant source and generated branch commits, Actions logs,
   and state-cache key metadata.
3. Rotate or revoke affected credentials through GitHub; DistWitness defines no
   additional secret.
4. Compare workflow/action pins and generated-branch contents with a known-good
   source commit.
5. Repair on `main`, run the full offline gate, then perform a manual live run.
6. Rebuild `gh-pages` after restoring a trusted workflow cache or establish a
   documented new baseline.
7. Publish a factual incident note without overstating affected packages.

For a source-data incident, preserve explicit unavailable/stale states and link
to upstream status. Do not infer package compromise from an API outage.

## Troubleshooting

- **Lock held:** confirm no other DistWitness process or workflow is running;
  do not delete `.lock` while a process is active.
- **No selected release:** inspect whether only pre-releases exist, the Index
  API version list is malformed, or the bounded 20-candidate release lookup
  contains no files; enable pre-releases only deliberately.
- **No events on first run:** expected; the first run is a baseline.
- **No duplicate event on repeat:** expected deterministic behaviour.
- **Build works but live run fails:** run `doctor`, then `scan --verbose`; do not
  expose headers or tokens in issue reports.
- **Schedule stopped after inactivity:** re-enable and manually dispatch it.

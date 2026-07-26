# State and public JSON schemas

Review date: 2026-07-27

DistWitness versions persistence records separately from generated public
contracts. A version change is explicit even when the migration can be applied
automatically.

“Private state” below means an internal application contract rather than a
public JSON API. It is not a confidentiality label. Local state is ignored by
Git, while scheduled state is held in a workflow cache and excluded from
the Pages deployment artefact; neither location may contain secrets or private
package data.

## Current versions

| Contract | Version | Notes |
| --- | ---: | --- |
| Private `state/state.json` root | 3 | Adds bounded source-health history |
| Package snapshot | 2 | Records release-discovery provenance |
| Change event | 1 | Unchanged |
| Run result | 1 | Unchanged |
| Source-health observation | 1 | Aggregate result for one source and run |
| Public `data/current.json` root | 3 | Adds measured source-health summaries |
| Public `data/events.json` root and events | 1 | Unchanged |
| Public `data/health.json` root | 1 | Bounded source-health observations |

Package snapshot v2 records:

- `release_discovery`, either `pypi-index-v1` or
  `legacy-project-json`;
- `index_api_version`, the observed `major.minor` Index API version for a fresh
  Index observation, or `null` for migrated historical state.

State v3 adds `source_health_history`. Each observation records the source,
completion time, current status, checked packages, checks without a recorded
source error, total errors, and retryable errors. It does not claim to measure
individual HTTP requests or source correctness. History follows the configured
event-retention window and is additionally capped at 1,000 complete run groups.
Each retained run must contain exactly one internally consistent observation
for each of the three sources; incomplete or duplicate groups fail validation.

## Private state migration

Loading known historical state performs a deterministic in-memory migration:

1. A v1 root first applies the phase-two package migration. Each package
   snapshot moves to schema v2 with
   `release_discovery: "legacy-project-json"` and
   `index_api_version: null`.
2. A v1 or v2 root receives an empty `source_health_history`.
3. The root changes to schema v3.
4. Change-event and run-result records remain schema v1.
5. Strict v3 model validation runs after the transformation.

Loading or `validate` never rewrites the original file. The next successful
non-dry run writes state v3 through the normal locked, atomic replacement path
and adds the first three real health observations. A package whose collection
fails keeps its prior snapshot and explicit provenance label.

Migration labels and an empty health baseline are collection provenance, not
package changes, so they do not create change events or synthetic operational
history.

## Public health contract

`data/current.json` schema v3 exposes per-source summaries derived from retained
observations: current status, exact run-status counts, exact package-check
counts, observation-window boundaries, and maturity. Fewer than seven retained
run observations are labelled `baseline`; seven or more are labelled
`measured history`.

`data/health.json` schema v1 exposes the bounded observations themselves without
source-error messages, raw responses, request headers, or secrets. A package
check counted as successful means the run recorded no error for that package
and source. It is not a claim that upstream data was complete or correct.

## Failure and rollback boundary

Malformed state, mixed records that cannot satisfy the target contract, and
unknown root schema versions fail closed. DistWitness leaves the original file
untouched and does not silently establish a new baseline.

Before deployment, preserve trustworthy state-cache continuity or a private
state archive when policy requires it. The generated Pages artefact is not a
state backup. Recovery procedures are in [`OPERATIONS.md`](OPERATIONS.md).

Generated public JSON is derived output and is not read back into private state.
Consumers must reject unsupported major contract changes or explicitly add
their own migration.

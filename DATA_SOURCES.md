# Data sources

Review date: 2026-07-26

This document records the source contract used by DistWitness. It is a
technical review, not legal advice. Terms can change; operators should recheck
them before public launch and periodically thereafter.

DistWitness uses documented APIs only. It does not scrape HTML, download
distribution files, copy package descriptions or README content, or mirror
advisory bodies.

## PyPI Index API

- **Operator:** Python Software Foundation (PSF)
- **Endpoint:** `GET https://pypi.org/simple/{project}/` with
  `Accept: application/vnd.pypi.simple.v1+json`
- **Purpose:** obtain the authoritative project version set and select the
  highest eligible PEP 440 version
- **Fields retained:** normalised project name, negotiated API version, and the
  selected version
- **Fields validated but not retained:** the bounded version list and files
  array cardinality
- **Fields deliberately omitted:** distribution URLs, file hashes from this
  response, project status, and the raw response
- **Version policy:** DistWitness requires Index API v1.1 or newer, fails closed
  on an unsupported major version, and warns while using known fields from a
  newer v1 minor version
- **Selection bounds:** invalid PEP 440 entries are ignored; exact duplicate
  version strings are rejected; pre-releases are opt-in; at most 10,000 version
  strings and 25,000 file entries are accepted; the complete Index response is
  capped at 8 MiB
- **Polling:** once daily in the provided workflow, with manual runs available
- **Caching:** in-process ETag and Last-Modified conditional requests where the
  server supplies validators; no persistent raw-response cache
- **Request policy:** fixed host, identifying User-Agent, sequential package
  pacing, bounded retries and bytes, at most 100 configured packages
- **Attribution:** records link to the corresponding authoritative PyPI release
- **Terms/findings:** PyPI API use is subject to the PyPI Terms of Service,
  Acceptable Use Policy, and privacy policy. The terms prohibit abusive or
  excessively frequent use and use for spam. The acceptable-use policy
  distinguishes documented API collection from scraping while retaining
  usage/privacy obligations
- **Correction/removal:** correct source metadata through the package's PyPI
  maintainers or PyPI support. Remove a package locally from
  `config/watchlist.yml`; historical events then age out under configured
  retention.

Official references:

- <https://packaging.python.org/en/latest/specifications/simple-repository-api/>
- <https://policies.python.org/pypi.org/Terms-of-Service/>
- <https://policies.python.org/pypi.org/Acceptable-Use-Policy/>
- <https://policies.python.org/pypi.org/Privacy-Notice/>

## PyPI release-specific JSON API

- **Operator:** Python Software Foundation (PSF)
- **Endpoint:** `GET https://pypi.org/pypi/{project}/{version}/json`
- **Purpose:** obtain compact metadata for each descending Index API candidate
  until a release with files is found
- **Fields retained:** project/display name; selected version; release
  filenames; SHA-256; byte size; package type; ISO upload timestamp; Python
  version/tags; `requires_python`; yanked state/reason; `requires_dist`;
  `license_expression`; bounded declared license; licensing classifiers; valid
  public project URLs
- **Fields deliberately omitted:** descriptions, README content, people,
  emails, ownership roles, download URLs, MD5/BLAKE2 digests, download counts,
  and raw responses
- **Selection bounds:** at most 20 descending eligible versions are queried and
  at most 200 files are accepted for the selected release. A 404 response or a
  release with no files advances to the next candidate.
- **Deprecated boundary:** DistWitness does not call the project-level
  `GET /pypi/{project}/json` endpoint and does not consume its deprecated
  `releases` field
- **Polling, caching, terms, attribution, and correction:** the same bounded
  PyPI policy described above

Official reference:

- <https://docs.pypi.org/api/json/>

## PyPI Integrity API

- **Operator:** Python Software Foundation (PSF)
- **Endpoint:** `GET https://pypi.org/integrity/{project}/{version}/{filename}/provenance`
- **Purpose:** observe whether PyPI reports PEP 740 provenance for each selected
  release file and retain bounded reported publisher identity fields
- **Fields retained:** availability state; publisher kind, repository,
  workflow, and environment when present; attestation count; observation time;
  authoritative endpoint link
- **Fields deliberately omitted:** attestation envelopes, signatures,
  statements, transparency-log proofs, claims, and raw responses
- **Status interpretation:** 200 means provenance is available; 404 means the
  file has no provenance; 403 means access is temporarily disabled. Failed,
  unsupported, and malformed responses remain separate states.
- **Verification boundary:** DistWitness reports API availability and publisher
  metadata; it does not claim independent cryptographic verification.
- **Polling/caching/terms:** same bounded daily PyPI policy described above
- **Correction/removal:** corrections belong in the PyPI provenance record.
  Local source removal follows the same watchlist/retention process.

Official reference:

- <https://docs.pypi.org/api/integrity/>

## OSV API

- **Operator:** OSV.dev project; service infrastructure is maintained in the
  `google/osv.dev` open-source repository
- **Endpoints:** `POST https://api.osv.dev/v1/querybatch` and bounded
  `GET https://api.osv.dev/v1/vulns/{id}` detail requests
- **Purpose:** query the exact selected PyPI package/version and retain enough
  metadata to identify and prioritise a reported advisory
- **Fields retained:** advisory ID; aliases; exact affected package/version;
  severity type/score and a label only when reliably represented; published and
  modified timestamps; bounded authoritative references; OSV source link
- **Fields deliberately omitted:** summary, details/advisory body, database
  notes, credits, and raw responses
- **Polling:** one batch sequence per daily run, with at most 50 queries per
  request, five pages per query sequence, 100 detail records, and bounded
  response bytes
- **Caching:** in-process conditional GET caching for detail records when
  validators are available; no persistent raw-response cache
- **API findings:** the official API currently advertises no rate limit and a
  32 MiB HTTP/1.1 response limit. DistWitness applies substantially smaller
  limits. Batch response order is guaranteed to match input order; pagination
  tokens are per query and are handled independently.
- **Licensing/terms constraint:** OSV service code is Apache-2.0, but aggregated
  advisory records originate in multiple databases and can carry
  source-specific terms. DistWitness therefore does not republish advisory body
  text and instead exposes identifiers, bounded factual fields, and links to
  authoritative records. Operators remain responsible for the applicable
  source terms.
- **Correction/removal:** follow the authoritative reference or upstream
  advisory database named by the OSV record. Remove the watched package locally
  through the watchlist; retained events expire under configured retention.

Official references:

- <https://google.github.io/osv.dev/api/>
- <https://google.github.io/osv.dev/post-v1-querybatch/>
- <https://google.github.io/osv.dev/get-v1-vulns/>
- <https://ossf.github.io/osv-schema/>
- <https://github.com/google/osv.dev>

## Identity and affiliation

DistWitness uses no PyPI, PSF, OSV, Google, OpenSSF, or package-maintainer logos.
Source names are factual attribution. The project is independent and makes no
endorsement or affiliation claim.

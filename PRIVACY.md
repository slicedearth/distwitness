# Privacy

DistWitness processes public Python package-release, provenance, and
vulnerability metadata. The application itself collects no personal data.

The generated site:

- has no accounts or authentication;
- sets no cookies;
- uses no analytics, telemetry, advertising, fingerprinting, or error-reporting
  SaaS;
- has no contact forms;
- makes no visitor-side API requests;
- does not collect or store visitor IP addresses or request logs.

A static hosting provider may independently process ordinary access information
under its own policies. That processing is outside DistWitness and is not
forwarded to the application.

Locally configured watchlists remain in the repository in which the operator
places them. Public hosting makes the configured package watchlist and
generated findings public. Operators should not place secrets or private index
names in the public configuration.

Generated source-health history contains only source names, timestamps,
aggregate package-check counts, and error counts. It excludes raw responses,
request headers, source-error messages, visitor activity, and operator
environment data.

Scheduled operation retains compact comparison state in a GitHub Actions cache,
not in the source or `gh-pages` branch. Cached state contains normalised public
package metadata, retained review events, aggregate source observations,
operational timestamps, and bounded source diagnostics. It excludes raw
responses, request headers, credentials, private indexes, operator environment
data, and maintainer contact fields. Actions caches are an operational
continuity mechanism, not secret or archival storage; eligible workflow
contexts may restore the default-branch cache and GitHub may evict it.

Upstream PyPI responses can contain personal fields, but DistWitness does not
retain maintainer names, emails, ownership roles, or description text. OSV
advisory bodies and credits are not retained.

To remove a watched package, edit `config/watchlist.yml`. Existing retained
events age out according to `retention_days`; an operator can deliberately
rotate generated state using the documented recovery procedure in
`docs/OPERATIONS.md`.

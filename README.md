# Amaterasu display settings

An independently built display-policy extension for Amaterasu. It resolves
configuration for a stream and proposes changes to a coordinator-selected
physical or virtual display resource. The resource owner applies and restores
changes through the composed lifecycle contract. [The parity ledger](docs/PARITY.md)
tracks platform coverage and remaining qualification.

The policy validates requested modes, scaling, HDR and layout. Native changes
require coordinator admission and a selected resource owner. This plugin does
not create, retain or remove virtual screens.

## Local development

Check out Amaterasu as `../amaterasu`; the module SDK dependency currently uses
that sibling checkout. Build with `CARGO_BUILD_JOBS=2 cargo test` and
`cargo clippy --all-targets -- -D warnings`. The sibling checkout must provide
compatible public SDK and extension API versions; packaging those APIs for
portable distribution and publishing this plugin are separate future work.
No private Amaterasu Rust crates are imported directly.

No local build or unit test modifies displays. Tests do not establish that native
mode setting, recovery, capture binding, or either platform works on hardware.

The composed planner supports physical targets when a compatible v2 resource
producer exists. Linux and Windows native behavior and complete streaming still
require integration and hardware qualification. Unknown operations remain fenced
for coordinator reconciliation.

`examples/component-linux.json` is a component-manifest template; the packager
replaces its hash and size. `examples/lifecycle-api-approvals.json` shows the
separate operator-installed approvals for lifecycle and settings calls. The
generated settings descriptor and the module are disabled by default; the
operator must select compatible services and approve their grants. Policy
approval is not part of the signed component manifest.

## Upgrading existing settings

Descriptor revision 2 removes retention, retention seconds, pause keepalive and
pause enforcement from display settings. Revision-1 registry documents are not
automatically migrated or deleted. Use a fresh profile and an explicit settings
export/import to split configuration from virtual-screen lifecycle settings.
Validate both imports before enabling effects. Retire owned resources under the
old provider first; this extension does not adopt its leases or native journal.
The export/import tooling and composed lifecycle path are still being integrated.

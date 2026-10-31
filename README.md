# Amaterasu display settings

An independently built display-policy extension for Amaterasu. This repository
is under active development. Its lifecycle participant plans and delegates
owned virtual-display changes to selected public services. The current platform
coverage and remaining qualification are in [the parity ledger](docs/PARITY.md).

The policy validates requested modes, scaling, HDR, layout and retention. Native
display changes must be admitted by the shared session coordinator and delegated through public, selected Amaterasu services.
The virtual-display provider owns its native-resource journal and recovery; a
resource identity in an extension request does not grant authority.

## Local development

Check out Amaterasu as `../amaterasu`; the module SDK dependency currently uses
that sibling checkout. Build with `CARGO_BUILD_JOBS=2 cargo test` and
`cargo clippy --all-targets -- -D warnings`. The sibling checkout must provide
compatible public SDK and extension API versions; packaging those APIs for
portable distribution and publishing this plugin are separate future work.
No private Amaterasu Rust crates are imported directly.

No local build or unit test modifies displays. Tests do not establish that native
mode setting, recovery, capture binding, or either platform works on hardware.

Lifecycle operations use a bounded durable receipt window, a sequence watermark,
and separate cleanup obligations. Unknown effects require reconciliation. The
current source supports cooperative Wayland-owned displays; Linux physical
display mutation remains unavailable. The physical provider coordinates its own
leases and reads native topology, but cannot fence unrelated desktop or OS
changes. An interrupted resize can be reconciled without replaying the native operation;
if stream preparation was interrupted before publication, it remains fenced for
future scoped cleanup. Physical and action coverage is tracked in the parity ledger.

`examples/component-linux.json` is a component-manifest template; the packager
replaces its hash and size. `examples/lifecycle-api-approvals.json` shows the
separate operator-installed approvals for lifecycle and settings calls. The
generated settings descriptor and the module are disabled by default; the
operator must select compatible services and approve their grants. Policy
approval is not part of the signed component manifest.

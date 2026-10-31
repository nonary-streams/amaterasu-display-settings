# Amaterasu display settings

An independently built display-policy extension for Amaterasu. This repository
is under active development; the native lifecycle participant and registration
are not yet wired. Do not select this library as a production component until
the requirements in [the parity ledger](docs/PARITY.md) are implemented and
qualified.

The policy validates requested modes, scaling, HDR, layout and retention without
performing native effects. Native display changes must be admitted by the shared
session coordinator and delegated through public, selected Amaterasu services.
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

The receipt-store client retains at most 64 operation records and fails closed
at capacity. Safe retirement needs a coordinator-authorized epoch and replay
watermark; the store must not be used for production lifecycle effects until
that contract and recovery integration are available.

`examples/component-linux.json` is a component-manifest template for an
isolated settings-validation smoke test; the packager replaces its hash and
size. `examples/settings-validation-approval.json` illustrates a separate
operator-installed API approval for registry and management callers. Neither
file enables display lifecycle or action behavior, and policy approval is not
part of the signed component manifest.

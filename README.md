# Amaterasu display settings

This public repository contains an independently built display-policy extension
for Amaterasu. It resolves stream settings and proposes configuration and
restoration for a coordinator-selected display resource. The separate
[virtual-screen extension](https://github.com/nonary-streams/amaterasu-virtual-screen)
creates and owns the session-scoped virtual screen and its native lease; it
executes admitted controls. The lifecycle coordinator authenticates the handoff
and orders cleanup. This settings extension does not allocate, retain or remove
virtual screens.

Configuration and its restore obligation are stream-scoped. On pause the stream
is retired and its display settings are restored; the application and the
session-owned virtual screen are retained under the owner's default policy.
Resume establishes a new stream and requests configuration again. Timed
retention, pause enforcement and keepalive are not supported by the current
virtual-screen owner. Unknown or failed cleanup remains fenced for recovery.

The current composed planner supports SDR resolution and refresh choices, with
HDR and scale preserved. It rejects HDR streams or active HDR, HDR overrides,
scale changes and highest-available refresh. Virtual layouts are limited to
preserve, exclusive and extended; physical targets require preserved layout and
a compatible v2 producer, which is not yet available. Some multi-session cases,
native behavior and end-to-end streaming remain unqualified. Known preserved
HDR, scale and layout values must match after the control; unknown values require
the owner's snapshot-bound preservation proof. Restored handoffs also require a
matching snapshot and preservation proof.

## Local development

Building this public repository currently requires access to a compatible
private Amaterasu Core source checkout at `../amaterasu`. `Cargo.toml` uses
path dependencies on its module SDK and configuration-schema crates; the SDK
and extension API are not yet independently distributed. With that checkout,
run `CARGO_BUILD_JOBS=2 cargo test` and `cargo clippy --all-targets -- -D warnings`.
The extension consumes the SDK's public contracts, but a standalone public
checkout of this repository is not sufficient to build it today.

No local build or unit test modifies displays. Tests do not establish that native
mode setting, recovery, capture binding, or either platform works on hardware.

A test using the real broker, state service, lifecycle coordinator and both
extensions completed ten streams with alternating modes, active and paused
session endings, and a second session using the same native domain. The native
display and capture backends were simulated. The first two keyboard-triggered
removals also completed; further action lifecycle testing remains in progress.
These results do not establish native mode setting, capture, streaming or
hardware behavior. The virtual-screen owner currently supports Linux; its
Windows startup is fenced, and Windows qualification remains outstanding.

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
old caller and provider first; the new virtual-screen owner does not adopt old
caller-scoped leases or native journals, and settings documents do not transfer
native ownership.
The Core repository's `scripts/export_session_extension_split.py` can produce a
non-mutating, reviewable split plan for a fresh destination. It retains settings
fields here and maps the four lifecycle fields to virtual-screen; it validates
candidate values against supplied descriptors and requires an explicit owner
`enabled` choice. It does not contact the registry, apply imports, validate with
providers, or migrate an existing state root. It has been exercised with the
legacy and display-v2 descriptors and a draft owner descriptor; the latest owner
descriptor and live import still need validation. See the Core repository's
`docs/session-extensions-local-profile.md` for the procedure and limits.

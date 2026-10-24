# Privilege boundary v2-A.1 qualification record

This is the historical initial A1 checkpoint. The [production continuation](privilege-v2-a1-continuation.md), [native prerequisite proofs](privilege-v2-native-prerequisites.md) and [PTU follow-up](privilege-v2-ptu-handoff.md) record subsequent qualification; the pending states below describe the initial run. The [commit checkpoint](privilege-v2-commit-checkpoint.md) explains the retained source hashes.

Specification: `23OCT26-A01-privilege-boundary-v2-A.md`, Rev 2-A.1, 23 October 2026. Baseline: `d138965c9b6f9e3c53a916813a7376757f6ac727` (v0.6.7). The initial worktree was clean; no applicable `AGENTS.md` was present in the repository or its ancestors. No v2-B implementation is included.

This is an **A1 implementation checkpoint, not completion or release qualification of v2-A.1**. See [machine-readable evidence](privilege-v2-a1.json) for actual commands, versions, inputs, outcomes and hashes. Historical SRT/G3 records do not qualify this changed application artifact.

| Milestone / proof | State |
| --- | --- |
| A1 application ACL and exact source contract | Implemented; automated runtime and drift proofs run |
| A-S1 generated-context ACL | Passed: registered canary denied at ACL, zero executions; allowed production handler dispatches using isolated config; other window and remote origin denied; separate no-ACL control proves canary registration |
| A-S1 native dialog bridge | Passed in isolated Wry/WebView2 fixture: two actual `window.confirm` calls returned Cancel through the pinned initializer; no NetworkManager, capture, configuration writes or native network mutation |
| A1 production native smoke | Pending: actual settings, address-removal and DHCP workflows, discovery, playback, PTU, and video/notice interaction on a controlled application/hardware setup. The bridge fixture is not this full workflow smoke |
| A2 / A-S2 native runner | Deferred: A1 exit qualification incomplete; fixed-script/data, child-tree, actual caller abort, retained outcome and conflicting-write proofs not executed |
| A2 / A-S4 ownership | Deferred: two-process and lone-host crash/restart/reconciliation proofs not executed |
| A3 / A-S3 firewall and installation | Deferred: no isolated Windows firewall/installer fixture supplied or exercised; no firewall policy or installed files changed in this work |
| A3 / A-S4 binding | Deferred: unrelated Wi-Fi/VPN/virtual changes, full inventory and explicit rebind matrix not executed |
| A4 release qualification | Pending; installed release manifest, migration, rule shape, installer template/gate lifetime, uninstall and G3 artifact/hash closure remain separate pending gates |

Milestones remain ordered. The unqualified A1 exit is not treated as permission to start dependent A2/A3 integration. `list_vpn_interfaces` remains consistent in all five A1 inventories, as allowed by the specification's A1 exit contract; its one-for-one rename to `list_bind_interfaces` belongs to A3. No B-only command was added. Release execution level remains `requireAdministrator`; development/test Common Controls behavior is preserved.

## A1 implementation

`build.rs` supplies a nonempty application manifest to both Windows branches and the other-platform build path. The main capability grants exactly the 46 application allow identifiers and nine specified plugin identifiers. The native notification plugin remains registered for Rust use, without a renderer grant. The 46 generated permission files are committed, each containing only its matching allow and deny command payloads.

The renderer surface drops the 16 unreachable registrations plus `report_scan_result`, their handlers and obsolete private helpers/stubs. Exactly fifteen wrapper functions were removed, including unused `retryPlayback`; the called `reassertPlayback` wrapper remains. Backend scan-completion publication is preserved. Existing fake seams, native adapter identity, watcher infrastructure and operation serialization are unchanged.

`check-ipc-allowlist.mjs` is included in `check:contracts`, frontend builds, and both Quick/full `check.ps1` paths. `npm test` includes independent drift seeds for each of the five inventories, generated allow and deny payloads, extra grants/files, duplicates, dynamic invocation and unsupported indirection.

## Supported wrapper convention

- Export named function declarations from `src/lib/tauri-api.ts`. Each command wrapper contains exactly one direct private `invoke` call with a string literal command. `onEvent` is the separate event helper.
- Production source uses named imports (including import aliases), namespace imports with `.property`, and chains of `const` identifier aliases. Direct callback value references count as uses. Imports without a value use, comments, declaration names, type-only references and `.d.ts` files do not count.
- Mutable/destructured aliases, namespace escape, computed property access, unresolved properties, re-export indirection and `.call`/`.bind`/`.apply` fail with a source location. Raw invoke access outside the private boundary fails. Add support deliberately with a drift fixture before introducing another convention.
- This verifies source references and exact allowlist consistency. It does not build a whole-program call graph or claim runtime reachability. Native plugin registration and plugin permissions are checked separately from the application wrapper count.
- Generated TOML follows tauri-build 2.5.6's simple two-record format. Unexpected keys, duplicate fields or syntax outside that generated convention fail closed; the checker is not a general TOML parser.

## Reproduction and limits

Leave `POCKETSTREAM_RELEASE` unset for tests and native dialog smoke. Use the repository's configured GStreamer MSVC SDK, adding its `bin` directory to `PATH`. Run `npm test`, `npm run typecheck`, `npm run build`, `cargo test --lib --locked`, `cargo fmt --check`, and `cargo clippy --all-targets --no-deps --locked -- -D warnings`. The ACL-only proof is `cargo test --lib --locked ipc_acl_tests -- --nocapture`.

The native fixture is `cargo run --example acl_native_smoke --locked`. Under automation, launch the built example with an outer 45-second limit. It replaces only the generated context's assets and window configuration; it retains the real ACL and plugin initializers. Native Cancel is posted only to dialog windows owned by that fixture PID. Version, event subscribe/unsubscribe, minimize, maximize/restore and close use the actual renderer bridge. Resize uses the native window API. The updater check never installs an update; endpoint failure, if any, is recorded separately from ACL dispatch. Production confirmation paths also have frontend fake-seam coverage, but full application smoke remains pending above.

The restricted sandbox denied Windows CIM adapter queries and prevented the first GUI fixture from reaching initialization; the ordinary frontend build also hit a parent-directory resolution restriction. These are recorded as unsuccessful sandbox attempts, not ignored successes. Only the authorized build, read-only/native regression checks and isolated GUI fixture were retried outside the sandbox. Firewall/install qualification was not attempted on the developer host.

The release-manifest branch proof, if present in the JSON, is a development-profile executable built with `POCKETSTREAM_RELEASE=1` and inspected without launching it. It is not an installed release-package result. All installed-package and G3 fields remain pending.

Renderer/media compromise still occurs in an elevated host until v2-B is implemented and qualified. A1 reduces renderer authorization; it does not establish privilege separation or close A01.

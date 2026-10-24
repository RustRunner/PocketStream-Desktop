# Rev 2-A.1 commit checkpoint

The user authorized these commits after the controlled A1 session ended. No co-author trailers were added. No installed executable was replaced and no changes were pushed.

| Commit | Scope |
| --- | --- |
| `4cae14b0f9a32bd994a5eee70c643aac3c0834ec` | A1 exact 46-command ACL, surface reduction, drift checks and ACL/dialog fixtures |
| `9bb4b20ca0b5033d4469a9652137cd75e2568e92` | Test-only native runner, executor and ownership prerequisite fixtures |
| `43e7954af96e9acff5d57be31da766648c3daa06` | PTU idle-selection halt alarm correction and workflow regressions |

[Production smoke](privilege-v2-a1-continuation.md) records settings and both confirmation Cancel paths on development image `be1be2c86338167fe4540124b72f005d94ad948f2ce23327323c52ea590dffc1`, discovery/live playback on release image `c483047a2d962b153cc41069daa9041d6168a25c952672f295e71a80ab292d8f`, and the corrected PTU workflow on release image `4337b1dca9a158a9e71c24d2c8b34079cdf2ac4e8b167d0f7e736ab0413e059e`. These are separate historical artifacts; no single-artifact repeat of every workflow is claimed. The final PTU candidate passed `.202` role/query smoke without the red toast, user-observed Home movement/stop and normal Close/process exit. The original profile was restored byte-for-byte and native bindings were preserved.

Recorded validation passed 764 ordinary Rust tests, four opt-in Windows process prerequisites and the final 184 frontend tests, including 29 PTU workflow tests. Typecheck, contracts, production frontend/release builds, formatting and all-targets Clippy passed at their recorded checkpoints. The [native prerequisite record](privilege-v2-native-prerequisites.md) and [PTU record](privilege-v2-ptu-handoff.md) identify the exact commands, source inputs, artifacts, failed earlier attempts and limits.

Source hashes in the existing JSON records describe qualification-time raw file bytes and remain unchanged. Before commit documentation edits, all 83 inputs in the PTU record and all 81 inputs in the native prerequisite record matched the worktree; all 49 top-level evidence-file hashes across the continuation records matched. The original A1 record differed only in the later test-only Cargo dependencies and network module wiring, already described in the continuation. README, release notes and the initial A1 narrative were then updated to show current status. Their original bytes are retained locally under ignored `src-tauri/target/commit-prep/qualification-source-docs/` (the narrative is named `docs__runtime-evidence__privilege-v2-a1.md`). The continuation's uncommitted-state wording was also made explicitly historical. These documentation changes do not represent a newly tested binary.

A2 production integration, A3 and A4 remain incomplete; B implementation stays deferred. Firewall/install qualification requires an isolated Windows fixture. Cross-account/logon/integrity execution, the bind matrix, a directional-axis release matrix, installed-package qualification and G3 closure remain pending. The other PC's missed PTU discovery/adoption cause remains undetermined because its log is unavailable; `.74` is an observed unidentified node, not the verified PTU. The release manifest remains `requireAdministrator` and the application contract remains 46 commands.

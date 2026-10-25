# Runtime ownership after A03 implementation

This describes the implementation following the Revision 3 early-start track
from `b849dfc` for slices 1–6 and the explicitly rescheduled streaming slices
7–10 from reviewed `6f8a727`. The user authorized that implementation track on
2026-10-25 before A4 qualification. **A4 remains
incomplete/deferred; B remains deferred.** Source checks do not qualify hardware,
physical timing, recovery, installation, firewall behavior or release artifacts.
See the [implementation record](../runtime-evidence/a03-revision3-implementation.md).
The [streaming record](../runtime-evidence/a03-streaming-implementation.md)
tracks the separately authorized slices, starting at `6f8a727`.

The composition root in `lib.rs` shares one `Arc<AppConfig>`, one
`Arc<NetworkManager>` and one `Arc<StreamManager>`. Rust command extractors use
these same managed types. Renderer DTOs, arguments, events, persistence and
frontend mirrors retain their existing contracts.

| Owner | Authority and dependencies |
| --- | --- |
| `NetworkManager` | One non-reentrant `discovery_op` lifecycle lock; sequences mode, selection, start/stop, restore, refresh and cleanup across concrete owners. Manual admission remains here in `manual_address.rs`; refresh remains here in `adapter_refresh.rs`. |
| `StreamManager` | Constructs concrete streaming owners with bridge/readiness dependencies, delegates the unchanged command-facing operations and starts existing process-lifetime tasks through Tauri's runtime. It retains no production playback/relay state or mutation workflow. |
| `AdapterSelector` | Proposed/committed selection, presence control/task, local MAC identities and latest-selection watch. The facade retires old work/routes before commit. Watch notifications occur at the existing event points, including repeated identical observations. |
| `BindingStore` | `AddressIo`, address-work serialization, address pause/generation/active flags, adopted routes/metadata, durable temporary-address adapters, adoption IDs, liveness and flush cadence. Manual helpers extend this owner in `manual_address.rs`; existing fakes/seams remain. Automatic live publication also enters this owner. |
| `CaptureSession` | Listener, incarnation identity/flag, signal, candidates, solicitation sender and prior capture joins. Retire the incarnation, deactivate/clear, then park the join. Attach drains prior joins with the existing bounded policy. |
| `DiscoverySession` | Session generation/active/clock, legacy ARP map, sweep launch and watchdog/adopt handles. `adopt_loop.rs` contains the moved loop and its existing local dwell, cache, DHCP, ghost and cooldown state. |
| `DeviceRegistry` / `DeviceListEmitter` | Canonical device state and the single 150 ms coalescer. The emitter is constructed before hydration; construction starts no task. |
| `ScanWorkflow` | Duplicate-scan admission and cancellation-safe `ScanGuard`; uses readiness and the existing discovery-session fence. |
| `ping_dot::Pinger` | Pinger handle, cancellation and await policy. Its initialization flag replaces the former global application's initialization point; a read-only clone in readiness preserves diagnostic admission after stop. |
| `CameraReadiness` | Narrow read facade over selection/presence, binding views, registry and session fences; bound/unbound readiness, latest selection, verification wake, adopted addresses and diagnostic probe. Snapshot probes retain `try_lock`; no lifecycle/address-lock acquisition was added. |
| `native_operations` / `LocalExecutor` | Existing private process-wide executor and `NATIVE_SCOPE`, operation identity, cancellation, worker, retained completion/observation, acknowledgment and recovery/shutdown barriers. Address and firewall work share this executor. |
| `bindings.rs` / `interface.rs` | Existing private topology fingerprint/revision and native/qualified metadata observation state. GUID resolution/migration and all-address exposure remain separate from selected-camera eligibility. |
| Composition / `MachineGuard` | InstallGate/HostOwner admission and owner-thread release spanning initialization, application work and final retained drain. |
| `PlaybackService` | Playback and recording Option fields, intent/instance epochs, lifecycle/wake, diagnostic task and supervisor; concrete readiness/selection context, surface and the single status publisher. `PlaybackSlot` exposes only a mutable playback projection of the retained common state mutex. |
| `RelayService` | Listener/desired/spec/health, settings/protocol transactions, intent/generation, lifecycle/wake/events/supervisor, topology and both firewall outcome and generation lease. `RelaySlot` exposes only relay mutation; its UDP guard reads playback occupancy while holding the common lock. Firewall dispatch still awaits the shared retained native executor inline. |
| `VideoSurface` | Native child HWND plus incarnation, serialized main-thread create/replace/reposition/visibility and conditional cleanup via AppBridge. Queued work checks the incarnation before touching a handle. |
| Status publication | `StatusPublisher` owns the existing watch; all synchronous and supervisor refresh points compose under the common mutex and deduplicate into that watch. The broadcaster uses AppBridge. |

Network owner fields are private outside the network module. Network-internal visibility
supports facade sequencing and the existing callback/fence adapters; it is not
an additional owner. Only owner lifecycle operations advance their generations.
The following shared views deliberately retain their original synchronization:

- `SweepFence` clones read the owning session/address/incarnation epoch and active
  flags. A stop/start cannot make an old fence current again.
- Capture callbacks retain candidate ingress, the selector's synchronous local-MAC
  set, the discovery legacy-map adapter, registry/emitter and config/bridge. They
  do not take facade lifecycle or address locks.
- Sweeps/watchdog retain capture-slot/prior-join/counter views and session fences.
  The watchdog keeps retire → park → start → install ordering. No second capture
  notification subscriber or poller was introduced.
- Adoption/probe seams retain `PendingIps` for existing cleanup/handover APIs;
  durable config intent remains cleanup authority. Adopted/metadata views used
  for candidate decisions are read-only; publication and adoption IDs enter
  `BindingStore`. The binding snapshot reads the session clock at its original
  point after binding/liveness snapshots.
- `PresenceDeps` and `DiscoveryDeps` contain concrete owner references, config,
  registry/emitter and bridge. They never retain a network or streaming facade.

`AppBridge` exposes serialized events and main-thread work. The composition root
retains the concrete `TauriBridge` and binds it once in setup, before any emitter
use. Before binding, events are dropped and main-thread requests return an error.
Owners receive `Arc<dyn AppBridge>`. Emission errors retain their existing handling.
`VideoSurface` uses the same bridge for all main-thread work. Its slot is updated
on the main thread during creation, before the oneshot reply. Conditional release
clears the matching incarnation synchronously; queued destruction, position and
visibility work protect replacement incarnations, including numeric HWND reuse.
Replacement destroys the previous child before attempting creation. Failure and
old Stop cleanup use the token captured before their asynchronous playback work.

Playback and relay receive `CameraReadiness` at construction, with the surface
and/or the single status publisher and their concrete state projection. There is
no late readiness slot or managed-state lookup. A no-readiness constructor path
exists only for existing in-memory scenarios. Production construction requires
the shared readiness dependency. Selection subscription is created when starting
the playback supervisor and consumed in its existing wait with verified-device
wake. Initial/latest, repeated, rapid and closed-watch cases remain covered by
logical tests; these do not measure physical notification latency.

The original common async state mutex deliberately remains in `state.rs` as
serialization storage for `PlaybackData` and `RelayData`. These keep all 25
original fields/types, including valid intermediate Option states. Each service's
state handle and lifecycle/epoch controls are private. `PlaybackSlot` returns
only a mutable playback projection; `RelaySlot` returns only a mutable relay
projection. Services never receive the unprojected mutex. Status has a read-only
composition API over the whole mutex. The facade's unprojected scenario view is
compiled only for tests. No business transitions live in this storage module.

That shared serialization preserves UDP admission without duplicating occupancy
in another claim object. Playback checks desired/live relay occupancy before
publishing its source; relay checks playback source after the healthy-no-op check,
at its original locked admission point. Desired failure, listener take/retirement,
replacement and stale Stop retain the same release points and errors. Tests cover
both start orders, concurrent admission, actual failed construction and old cleanup
preserving newer playback/listener claims. Separating serialization is optional
future work requiring equivalent evidence; it is not an A03 implementation gap.

Status samples both projections and runtime metrics under that same mutex.
`StatusPublisher` alone can write the existing watch; owners call its synchronous
refresh API at the original points. Playback's existing 1 Hz/Skip supervisor also
refreshes relay metrics while preview is idle; relay's existing 1 Hz/Skip fault
poller and event-driven refresh points remain. There is one deduplicated broadcaster
through AppBridge, with the unchanged 27-field DTO and no additional status bus.

The dependency guard in `check:contracts` rejects explicit and inferred managed
state lookups and Tauri handle/state imports in owners. There are **no temporary
network or streaming exceptions**. Permanent adapters are `lib.rs` (composition),
commands (IPC extraction), the bridge (application effects),
existing watcher/conflict monitor, `video_embed.rs`, and the named ACL fixture.
The watcher/conflict monitor and video embedding remain narrow OS adapters; the
ACL fixture exercises real IPC extraction. The streaming facade uses only Tauri's
runtime spawn adapter when setup starts tasks, without a handle/state import or
exception. This text check supplements manual ownership/lock review; it is not a
Rust dependency proof.

Native writer routes remain: manual address → `address_request`; mode →
`mode_request`; refresh → `refresh_request`; selection → `select_request`;
startup → `startup_reconcile`; automatic adoption/temporary cleanup → existing
`PendingAdoptOps`/`RealAdoptOps`/`AddressOps`; static mode → existing `StaticIpOps`;
firewall → existing retained firewall request. Request/recovery adapters alone
capture owned facade/config references and await complete workflows inside
`NATIVE_SCOPE`. No constituent native step was moved into a new task. Existing
write-availability checks, trusted typed runner, 30-second operation budgets,
post-observation, firewall generation leases and identity validation remain.

Caller cancellation requests cancellation; it neither releases the native barrier
nor admits another writer. Uncertain completions remain unavailable until recovery;
ordinary completions require matching acknowledgment. `drain` returns inside
`NATIVE_SCOPE`; outside it, unmanaged writers are joined without waiting for a
managed transaction that may require the caller's lifecycle/address lock. Shutdown
joins all retained work. These are intentionally different barriers.

Lock order remains lifecycle → address pause → address work. Manual address
admission has one ten-second timeout across all three acquisitions; Busy drops
partial guards and queues no later write. Mode warning/validation still precedes
pause, producer retirement, fresh identity/native work, post-failure observation,
reconciliation, persistence, hydration and conditional resume. Canceled requests
still suppress discovery/pinger resumption. Save failure prevents healthy route
publication; failed/uncertain temporary intent and removal tombstones are retained.

Streaming lock order retains the existing policies. Relay intent is published
before waiting for transaction/lifecycle gates. Full user transactions take the
transaction gate, then listener lifecycle, then short common-state projections.
Playback Stop advances its epoch and retires intent before waiting for playback
lifecycle; recording and supervisor teardown hold that lifecycle and take short
common-state projections. No common guard spans binding resolution, firewall
dispatch, listener shutdown/build or recording finalization. Status keeps the
original common-state → health/metric read order. Playback reads the synchronous
surface slot under its state guard without dispatching or waiting for main-thread
work; surface closures never take streaming state, so there is no reverse edge.

Firewall lease installation occurs under relay lifecycle before native dispatch.
Prior leases retire before replacement; Failed, Unavailable and uncertain outcomes
retain the old lease. Only Inactive clears the matching generation/role. Stop
captures listener and outstanding firewall generations separately and retries an
older retained lease. Late results cannot overwrite newer outcomes. Permitted
listener startup with unavailable automation still reports that actual outcome.
Policy-result closure seams exercise only this lease logic; native retention
continues through the existing shared executor and NATIVE_SCOPE inline.

Startup obtains InstallGate, then HostOwner, then releases InstallGate before
logging/config/native initialization. Existing prerequisites follow admission.
Owner construction starts no tasks and requires no entered runtime. Readiness is
injected when constructing streaming. Setup binds the bridge, starts the existing
playback/relay supervisors and status broadcaster through Tauri's runtime, then the NIC watcher
and conflict monitor. The asynchronous workflow hydrates cache/manual nodes and
starts presence. Windows retained recovery retires stale firewall policy and
requires Inactive, hydrates adoption history, qualifies fresh inventory, validates
saved identities/prefixes, observes affected addresses/DNS/routes, restores binding
intent, re-reads/validates and requires temporary ownership resolved before opening
writes. Failure remains blocked; no empty-success fallback/retry was added.
Non-Windows restoration remains a distinct branch. Selection/events follow;
discovery starts or pre-attaches according to mode/link/capture availability,
fallback watching starts only when needed, then the pinger starts. Capture is not
delayed behind media initialization.

Binding observation runs before camera refresh on both native notifications and
retry ticks, and before the fallback poller's existing three-second sleep. It
returns an observation to the watcher adapter, which emits the unchanged
`binding-topology-changed` payload and awaits streaming topology handling in the
same order. Repeated identical failures are suppressed; unchanged success still
retries an independently Unknown listener. Camera failure, discovery being off
and unrelated adapters do not suppress this path. Existing debounce/dirty/trailing
wake and five-second retry/Skip policies remain.

Session stop clears active/clock before joining adopt then watchdog callers with
their separate existing five-second waits/abort fallbacks. The facade then drains
eligible native work and performs the original best-effort address `try_lock`
cleanup. Sweep retains its 500 ms start delay and fence, without a new join/abort.
Presence stops/clears verification scope, waits five seconds then aborts if needed.
Pinger cancellation awaits its task without a new deadline. Capture stop parks
its native thread join without synchronously waiting. Emitter/status lifetime
and coalescing remain process-wide.

Playback/relay supervisors and the status broadcaster retain their process
lifetime; Stop retires intent, pipeline/listener and recording work without
inventing a supervisor shutdown phase. Diagnostic tasks remain owned by playback
and are aborted on Stop or replacement as before. GStreamer media, GLib thread
shutdown/join policy and recorder EOS/finalization budgets are unchanged. No
network owner holds a streaming facade and no media owner holds the network
facade; callbacks use concrete readiness/fence dependencies.

Actual Windows `ExitRequested` order remains:

1. Stop playback and relay concurrently within their existing five-second wait.
2. Stop presence, then await pinger stop.
3. Within the existing five-second wait, cleanup takes lifecycle, stops discovery
   and capture, drains eligible native work, pauses addresses, takes address work
   and reconciles temporary ownership. Committed bindings remain in Windows/config.
4. Await retained-native shutdown, with no new outer timeout/abort.
5. Stop the pinger again and repeat cleanup within its existing five-second wait.
   Failed/blocked cleanup remains recoverable on startup.
6. Release HostOwner on its owning thread after the application/drain lifetime.
   The separate maintenance entry still performs its own native shutdown.

There is no five-second total-exit promise or guarantee that every temporary
address is deleted. Qualification limits in the existing A4 checklist remain open.

//! Eager SRT listener runtime.
//!
//! All camera credentials and SRT access-control values are assigned through
//! typed GObject properties after a constant pipeline skeleton is parsed.
//! Runtime faults intentionally retain only fixed redacted text.

use glib::prelude::*;
use glib::value::ToValue;
use gstreamer as gst;
use gstreamer::prelude::*;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::caller_registry::{
    caller_stream_id, caller_unused_argument, canonical_caller_address, AdmissionDecision,
    CallerRegistry, CallerRegistryFault, MAX_SRT_CALLERS,
};
use super::relay::{
    RelayEventSender, RelayFaultEvent, RelayFaultKind, RelayRuntimeHealth, RelaySupervisorEvent,
    RestreamBuildFailure, RestreamRuntimeContext,
};
use crate::error::AppError;

const RTSP_PIPELINE_SKELETON: &str = "rtspsrc name=src latency=200 protocols=tcp \
    ! rtph264depay ! h264parse name=parse config-interval=-1 \
    ! mpegtsmux name=mux alignment=7 \
    ! srtsink name=sink mode=listener wait-for-connection=false authentication=true";

// `demux` and `parse` deliberately begin separate parse-launch chains. The
// first H.264 pad is linked explicitly by `install_udp_demux_handlers`.
const UDP_PIPELINE_SKELETON: &str = "udpsrc name=src ! tsdemux name=demux \
    h264parse name=parse config-interval=-1 \
    ! mpegtsmux name=mux alignment=7 \
    ! srtsink name=sink mode=listener wait-for-connection=false authentication=true";

const BUS_JOIN_TIMEOUT: Duration = Duration::from_secs(3);
const BUS_START_TIMEOUT: Duration = Duration::from_secs(1);
const BUS_POLL_INTERVAL: gst::ClockTime = gst::ClockTime::from_mseconds(100);
const DIAGNOSTIC_BIND_RELEASE_TIMEOUT: Duration = Duration::from_millis(500);
const DIAGNOSTIC_BIND_RETRY_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy)]
struct AdmissionSignalIds {
    connecting: glib::subclass::SignalId,
    added: glib::subclass::SignalId,
    removed: glib::subclass::SignalId,
}

struct PipelineParts {
    pipeline: gst::Pipeline,
    source: gst::Element,
    mux: gst::Element,
    sink: gst::Element,
}

/// Cheap fallback probe for faults already emitted by a callback or the bus
/// thread. Taking the pending event makes polling idempotent.
#[derive(Clone)]
pub struct SrtRuntimeProbe {
    pending: Arc<Mutex<Option<RelayFaultEvent>>>,
}

impl SrtRuntimeProbe {
    fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(None)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<RelayFaultEvent>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish(&self, event: RelayFaultEvent, event_tx: &RelayEventSender) {
        *self.lock() = Some(event.clone());
        let _ = event_tx.send(RelaySupervisorEvent::Fault(event));
    }

    pub fn poll_fault(&self) -> Option<RelayFaultEvent> {
        self.lock().take()
    }
}

#[derive(Clone)]
struct SrtCallbackContext {
    health: Arc<RelayRuntimeHealth>,
    fault_probe: SrtRuntimeProbe,
    event_tx: RelayEventSender,
    shutdown_requested: Arc<AtomicBool>,
    server_instance: u64,
    data_generation: u64,
}

impl SrtCallbackContext {
    fn new(
        runtime: &RestreamRuntimeContext,
        fault_probe: SrtRuntimeProbe,
        shutdown_requested: Arc<AtomicBool>,
        data_generation: u64,
    ) -> Self {
        Self {
            health: runtime.health.clone(),
            fault_probe,
            event_tx: runtime.event_tx.clone(),
            shutdown_requested,
            server_instance: runtime.server_instance,
            data_generation,
        }
    }

    fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    fn emit_fault(&self, kind: RelayFaultKind, reason: String) {
        if self.is_shutdown_requested() {
            return;
        }
        if let Some(event) = self.health.report_fault(
            self.server_instance,
            self.data_generation,
            kind,
            reason.clone(),
        ) {
            log::warn!("SRT relay runtime fault: {reason}");
            self.fault_probe.publish(event, &self.event_tx);
        }
    }

    fn emit_admission_fault(&self, fault: CallerRegistryFault) {
        self.emit_fault(
            RelayFaultKind::Capability,
            format!("SRT caller admission capability failure: {fault}"),
        );
    }
}

fn configuration_failure(message: impl Into<String>) -> RestreamBuildFailure {
    RestreamBuildFailure::configuration(AppError::Stream(message.into()))
}

fn require_property_type(
    element: &gst::Element,
    property: &'static str,
    expected: glib::Type,
) -> Result<(), RestreamBuildFailure> {
    let Some(spec) = element.find_property(property) else {
        return Err(configuration_failure(format!(
            "Bundled GStreamer SRT runtime lacks required property '{property}'"
        )));
    };
    if spec.value_type() != expected || !spec.flags().contains(glib::ParamFlags::WRITABLE) {
        return Err(configuration_failure(format!(
            "Bundled GStreamer SRT property '{property}' has an incompatible type or access mode"
        )));
    }
    Ok(())
}

fn require_signal(
    element: &gst::Element,
    name: &'static str,
    parameters: &[glib::Type],
    return_type: glib::Type,
) -> Result<glib::subclass::SignalId, RestreamBuildFailure> {
    let Some(signal_id) = glib::subclass::SignalId::lookup(name, element.type_()) else {
        return Err(configuration_failure(format!(
            "Bundled GStreamer SRT runtime lacks required signal '{name}'"
        )));
    };
    let query = signal_id.query();
    let actual_parameters: Vec<glib::Type> = query
        .param_types()
        .iter()
        .map(|parameter| parameter.type_())
        .collect();
    if actual_parameters != parameters || query.return_type().type_() != return_type {
        return Err(configuration_failure(format!(
            "Bundled GStreamer SRT signal '{name}' has an incompatible callback signature"
        )));
    }
    Ok(signal_id)
}

/// Validate the dynamic callback ABI before any listener bind. G2 proves this
/// exact contract against the pinned runtime; this check prevents a replaced
/// or older plugin from reaching a panic-prone dynamic signal marshal.
fn preflight_srt_capabilities() -> Result<AdmissionSignalIds, RestreamBuildFailure> {
    let sink = gst::ElementFactory::make("srtsink")
        .build()
        .map_err(|_| configuration_failure("Bundled GStreamer lacks the SRT sink element"))?;
    require_property_type(&sink, "authentication", glib::Type::BOOL)?;

    let socket_address = gio::SocketAddress::static_type();
    let connecting = require_signal(
        &sink,
        "caller-connecting",
        &[socket_address, glib::Type::STRING],
        glib::Type::BOOL,
    )?;
    let added = require_signal(
        &sink,
        "caller-added",
        &[glib::Type::I32, socket_address],
        glib::Type::UNIT,
    )?;
    let removed = require_signal(
        &sink,
        "caller-removed",
        &[glib::Type::I32, socket_address],
        glib::Type::UNIT,
    )?;
    Ok(AdmissionSignalIds {
        connecting,
        added,
        removed,
    })
}

fn parse_pipeline(description: &'static str) -> Result<PipelineParts, RestreamBuildFailure> {
    let element = gst::parse::launch(description)
        .map_err(|_| configuration_failure("Failed to construct the SRT relay pipeline"))?;
    let pipeline = element
        .downcast::<gst::Pipeline>()
        .map_err(|_| configuration_failure("SRT relay launch did not create a pipeline"))?;
    let source = pipeline
        .by_name("src")
        .ok_or_else(|| configuration_failure("SRT relay pipeline has no source element"))?;
    let mux = pipeline
        .by_name("mux")
        .ok_or_else(|| configuration_failure("SRT relay pipeline has no mux element"))?;
    let sink = pipeline
        .by_name("sink")
        .ok_or_else(|| configuration_failure("SRT relay pipeline has no sink element"))?;
    Ok(PipelineParts {
        pipeline,
        source,
        mux,
        sink,
    })
}

fn configure_sink(
    sink: &gst::Element,
    server_port: u16,
    bind_address: Option<&str>,
    passphrase: Option<&str>,
    latency_ms: u32,
) -> Result<(), RestreamBuildFailure> {
    require_property_type(sink, "localport", glib::Type::U32)?;
    require_property_type(sink, "localaddress", glib::Type::STRING)?;
    require_property_type(sink, "latency", glib::Type::I32)?;
    require_property_type(sink, "passphrase", glib::Type::STRING)?;
    require_property_type(sink, "poll-timeout", glib::Type::I32)?;
    let Some(key_length) = sink.find_property("pbkeylen") else {
        return Err(configuration_failure(
            "Bundled GStreamer SRT runtime lacks required property 'pbkeylen'",
        ));
    };
    if !key_length.flags().contains(glib::ParamFlags::WRITABLE) {
        return Err(configuration_failure(
            "Bundled GStreamer SRT property 'pbkeylen' is not writable",
        ));
    }

    sink.set_property("localport", u32::from(server_port));
    if let Some(address) = bind_address {
        sink.set_property("localaddress", address);
    }
    sink.set_property("latency", latency_ms as i32);
    // Keeps both regular shutdown and failed-candidate diagnostic teardown
    // bounded while still avoiding a busy poll inside the plugin.
    sink.set_property("poll-timeout", 100_i32);
    if let Some(passphrase) = passphrase.filter(|value| !value.is_empty()) {
        sink.set_property("passphrase", passphrase);
        sink.set_property_from_str("pbkeylen", "16");
    }
    Ok(())
}

fn configure_rtsp_source(
    source: &gst::Element,
    input_url: &str,
    username: &str,
    password: &str,
) -> Result<(), RestreamBuildFailure> {
    super::configure_tcp_rtspsrc(source).map_err(RestreamBuildFailure::configuration)?;
    for property in ["location", "user-id", "user-pw"] {
        require_property_type(source, property, glib::Type::STRING)?;
    }
    source.set_property("location", input_url);
    if !username.is_empty() {
        source.set_property("user-id", username);
        source.set_property("user-pw", password);
    }
    Ok(())
}

fn configure_udp_source(source: &gst::Element, udp_port: u16) -> Result<(), RestreamBuildFailure> {
    require_property_type(source, "port", glib::Type::I32)?;
    source.set_property("port", i32::from(udp_port));
    Ok(())
}

fn observed_probe_bytes(data: Option<&gst::PadProbeData<'_>>) -> u64 {
    match data {
        Some(gst::PadProbeData::Buffer(buffer)) => buffer.size() as u64,
        Some(gst::PadProbeData::BufferList(list)) => {
            list.iter().map(|buffer| buffer.size() as u64).sum()
        }
        _ => 0,
    }
}

fn observed_probe_arrival(data: Option<&gst::PadProbeData<'_>>) -> bool {
    matches!(
        data,
        Some(gst::PadProbeData::Buffer(_)) | Some(gst::PadProbeData::BufferList(_))
    )
}

fn calculate_bandwidth_kbps(current_bytes: u64, previous_bytes: u64, elapsed: Duration) -> f64 {
    let elapsed_secs = elapsed.as_secs_f64();
    if elapsed_secs < 0.001 {
        return 0.0;
    }
    let delta_bits = current_bytes.saturating_sub(previous_bytes) as f64 * 8.0;
    delta_bits / elapsed_secs / 1000.0
}

fn install_admission_handlers(
    sink: &gst::Element,
    signal_ids: AdmissionSignalIds,
    registry: Arc<CallerRegistry>,
    callbacks: SrtCallbackContext,
) -> Vec<(gst::Element, glib::SignalHandlerId)> {
    let connecting_registry = registry.clone();
    let connecting_callbacks = callbacks.clone();
    let connecting = sink.connect_id(signal_ids.connecting, None, false, move |values| {
        if connecting_callbacks.is_shutdown_requested() {
            return Some(false.to_value());
        }
        let address = match canonical_caller_address(values.get(1)) {
            Ok(address) => address,
            Err(fault) => {
                connecting_callbacks.emit_admission_fault(fault);
                return Some(false.to_value());
            }
        };
        let stream_id = match caller_stream_id(values.get(2)) {
            Ok(stream_id) => stream_id,
            Err(fault) => {
                connecting_callbacks.emit_admission_fault(fault);
                return Some(false.to_value());
            }
        };
        match connecting_registry.caller_connecting(address, &stream_id, Instant::now()) {
            Ok(AdmissionDecision::Accept) => Some(true.to_value()),
            Ok(AdmissionDecision::RejectStreamId) => {
                log::info!("SRT caller rejected: stream ID mismatch");
                Some(false.to_value())
            }
            Ok(AdmissionDecision::RejectCapacity) => {
                log::info!("SRT caller rejected: capacity");
                Some(false.to_value())
            }
            Err(fault) => {
                connecting_callbacks.emit_admission_fault(fault);
                Some(false.to_value())
            }
        }
    });

    let added_registry = registry.clone();
    let added_callbacks = callbacks.clone();
    let added = sink.connect_id(signal_ids.added, None, false, move |values| {
        if added_callbacks.is_shutdown_requested() {
            return None;
        }
        let unused = match caller_unused_argument(values.get(1)) {
            Ok(unused) => unused,
            Err(fault) => {
                added_callbacks.emit_admission_fault(fault);
                return None;
            }
        };
        let address = match canonical_caller_address(values.get(2)) {
            Ok(address) => address,
            Err(fault) => {
                added_callbacks.emit_admission_fault(fault);
                return None;
            }
        };
        match added_registry.caller_added(address, unused) {
            Ok(active) => log::info!("SRT caller accepted: {active}/{MAX_SRT_CALLERS}"),
            Err(fault) => added_callbacks.emit_admission_fault(fault),
        }
        None
    });

    let removed_registry = registry;
    let removed_callbacks = callbacks;
    let removed = sink.connect_id(signal_ids.removed, None, false, move |values| {
        if removed_callbacks.is_shutdown_requested() {
            return None;
        }
        let unused = match caller_unused_argument(values.get(1)) {
            Ok(unused) => unused,
            Err(fault) => {
                removed_callbacks.emit_admission_fault(fault);
                return None;
            }
        };
        let address = match canonical_caller_address(values.get(2)) {
            Ok(address) => address,
            Err(fault) => {
                removed_callbacks.emit_admission_fault(fault);
                return None;
            }
        };
        match removed_registry.caller_removed(&address, unused) {
            Ok(active) => log::info!("SRT caller removed: {active}/{MAX_SRT_CALLERS}"),
            Err(fault) => removed_callbacks.emit_admission_fault(fault),
        }
        None
    });

    vec![
        (sink.clone(), connecting),
        (sink.clone(), added),
        (sink.clone(), removed),
    ]
}

fn pad_is_h264(pad: &gst::Pad) -> bool {
    let caps = pad.current_caps().unwrap_or_else(|| pad.query_caps(None));
    caps.iter()
        .any(|structure| structure.name().as_str() == "video/x-h264")
}

fn install_udp_demux_handlers(
    pipeline: &gst::Pipeline,
    callbacks: SrtCallbackContext,
) -> Result<Vec<(gst::Element, glib::SignalHandlerId)>, RestreamBuildFailure> {
    let demux = pipeline
        .by_name("demux")
        .ok_or_else(|| configuration_failure("SRT UDP relay pipeline has no demux element"))?;
    let parser = pipeline
        .by_name("parse")
        .ok_or_else(|| configuration_failure("SRT UDP relay pipeline has no parser element"))?;
    let parser_sink = parser
        .static_pad("sink")
        .ok_or_else(|| configuration_failure("SRT UDP parser has no sink pad"))?;
    let parser_sink_weak = parser_sink.downgrade();
    let video_linked = Arc::new(AtomicBool::new(false));

    let linked_for_pad = video_linked.clone();
    let linked_for_done = video_linked;
    let callbacks_for_pad = callbacks.clone();
    let pad_added = demux.connect_pad_added(move |_demux, pad| {
        if callbacks_for_pad.is_shutdown_requested() || !pad_is_h264(pad) {
            return;
        }
        if linked_for_pad
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let Some(parser_sink) = parser_sink_weak.upgrade() else {
            callbacks_for_pad.emit_fault(
                RelayFaultKind::Capability,
                "SRT UDP relay parser disappeared during pad linking".into(),
            );
            return;
        };
        if parser_sink.is_linked() || pad.link(&parser_sink).is_err() {
            callbacks_for_pad.emit_fault(
                RelayFaultKind::Capability,
                "SRT UDP relay could not link its H.264 stream".into(),
            );
        }
    });

    let callbacks_for_done = callbacks;
    let no_more_pads = demux.connect_no_more_pads(move |_demux| {
        if !linked_for_done.load(Ordering::Acquire) {
            callbacks_for_done.emit_fault(
                RelayFaultKind::Capability,
                "SRT UDP relay found no H.264 video stream".into(),
            );
        }
    });

    Ok(vec![(demux.clone(), pad_added), (demux, no_more_pads)])
}

fn install_output_probe(
    sink: &gst::Element,
    bytes_sent: Arc<AtomicU64>,
    callbacks: SrtCallbackContext,
) -> Result<(gst::Pad, gst::PadProbeId), RestreamBuildFailure> {
    let sink_pad = sink
        .static_pad("sink")
        .ok_or_else(|| configuration_failure("SRT relay sink has no sink pad"))?;
    let probe_id = sink_pad
        .add_probe(
            gst::PadProbeType::BUFFER | gst::PadProbeType::BUFFER_LIST,
            move |_pad, info| {
                if callbacks.is_shutdown_requested() {
                    return gst::PadProbeReturn::Ok;
                }
                let observed_bytes = observed_probe_bytes(info.data.as_ref());
                if observed_bytes != 0 {
                    bytes_sent.fetch_add(observed_bytes, Ordering::Relaxed);
                }
                if observed_probe_arrival(info.data.as_ref()) {
                    callbacks.health.observe_buffer(
                        callbacks.server_instance,
                        callbacks.data_generation,
                        tokio::time::Instant::now(),
                    );
                }
                gst::PadProbeReturn::Ok
            },
        )
        .ok_or_else(|| configuration_failure("Failed to attach the SRT output probe"))?;
    Ok((sink_pad, probe_id))
}

fn spawn_bus_thread(
    bus: gst::Bus,
    callbacks: SrtCallbackContext,
) -> Result<
    (
        std::thread::JoinHandle<()>,
        tokio::sync::oneshot::Receiver<()>,
    ),
    RestreamBuildFailure,
> {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("srt-server-bus".into())
        .spawn(move || {
            callbacks.health.loop_started(callbacks.server_instance);
            let _ = ready_tx.send(());
            while !callbacks.is_shutdown_requested() {
                let message = bus.timed_pop_filtered(
                    BUS_POLL_INTERVAL,
                    &[gst::MessageType::Error, gst::MessageType::Eos],
                );
                let Some(message) = message else {
                    if callbacks.is_shutdown_requested() {
                        break;
                    }
                    continue;
                };
                if callbacks.is_shutdown_requested() {
                    break;
                }
                match message.view() {
                    gst::MessageView::Error(error) => {
                        let fault = super::classify::bus_fault(
                            &error.error(),
                            "SRT relay pipeline reported a GStreamer error".into(),
                            error
                                .details()
                                .and_then(|d| d.get::<u32>("rtsp-status-code").ok()),
                            error.debug().as_deref().unwrap_or_default(),
                        );
                        callbacks.emit_fault(
                            if fault.retryable {
                                RelayFaultKind::GstError
                            } else {
                                RelayFaultKind::PermanentGstError
                            },
                            fault.reason,
                        );
                    }
                    gst::MessageView::Eos(..) => callbacks.emit_fault(
                        RelayFaultKind::Eos,
                        "SRT relay pipeline reached end of stream".into(),
                    ),
                    _ => {}
                }
                break;
            }
            if let Some(event) = callbacks.health.loop_exited(
                callbacks.server_instance,
                callbacks.is_shutdown_requested(),
                "SRT relay bus thread exited unexpectedly".into(),
            ) {
                callbacks.fault_probe.publish(event, &callbacks.event_tx);
            }
            let _ = done_tx.send(());
        })
        .map_err(|_| configuration_failure("Failed to spawn the SRT relay bus thread"))?;

    if ready_rx.recv_timeout(BUS_START_TIMEOUT).is_err() {
        return Err(configuration_failure(
            "SRT relay bus thread did not start within 1 second",
        ));
    }
    Ok((handle, done_rx))
}

fn disconnect_handlers(handlers: &mut Vec<(gst::Element, glib::SignalHandlerId)>) {
    for (element, handler_id) in handlers.drain(..) {
        element.disconnect(handler_id);
    }
}

fn stop_candidate(
    pipeline: &gst::Pipeline,
    bus: &gst::Bus,
    shutdown_requested: &AtomicBool,
    handlers: &mut Vec<(gst::Element, glib::SignalHandlerId)>,
    output_probe: &mut Option<(gst::Pad, gst::PadProbeId)>,
    registry: &CallerRegistry,
) {
    shutdown_requested.store(true, Ordering::Release);
    let _ = pipeline.set_state(gst::State::Null);
    bus.set_flushing(true);
    disconnect_handlers(handlers);
    if let Some((pad, probe_id)) = output_probe.take() {
        pad.remove_probe(probe_id);
    }
    registry.clear();
}

fn diagnostic_bind_target(
    bind_address: Option<&str>,
    port: u16,
) -> Result<SocketAddr, RestreamBuildFailure> {
    let ip = bind_address
        .unwrap_or("0.0.0.0")
        .parse::<IpAddr>()
        .map_err(|_| configuration_failure("SRT relay bind address is invalid"))?;
    Ok(SocketAddr::new(ip, port))
}

fn classify_state_change_failure(bind_address: Option<&str>, port: u16) -> RestreamBuildFailure {
    let target = match diagnostic_bind_target(bind_address, port) {
        Ok(target) => target,
        Err(failure) => return failure,
    };
    let deadline = Instant::now() + DIAGNOSTIC_BIND_RELEASE_TIMEOUT;
    loop {
        match UdpSocket::bind(target) {
            Ok(socket) => {
                drop(socket);
                return configuration_failure("SRT relay pipeline failed to enter PLAYING");
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(DIAGNOSTIC_BIND_RETRY_INTERVAL);
            }
            Err(_) => {
                return RestreamBuildFailure::bind(AppError::Stream(
                    "SRT relay UDP listener could not bind".into(),
                ));
            }
        }
    }
}

pub struct SrtRestreamer {
    pipeline: gst::Pipeline,
    bus: gst::Bus,
    _source: gst::Element,
    _mux: gst::Element,
    _sink: gst::Element,
    signal_handlers: Vec<(gst::Element, glib::SignalHandlerId)>,
    output_probe: Option<(gst::Pad, gst::PadProbeId)>,
    caller_registry: Arc<CallerRegistry>,
    bus_thread: Option<std::thread::JoinHandle<()>>,
    bus_done_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    shutdown_requested: Arc<AtomicBool>,
    stopped: bool,
    server_generation: u64,
    server_instance: u64,
    data_generation: u64,
    health: Arc<RelayRuntimeHealth>,
    fault_probe: SrtRuntimeProbe,
    udp_ingest_port: Option<u16>,
    bytes_sent: Arc<AtomicU64>,
    bw_prev: Mutex<(u64, Instant)>,
}

impl SrtRestreamer {
    #[allow(clippy::too_many_arguments)]
    fn start_prepared(
        parts: PipelineParts,
        bus: gst::Bus,
        mut signal_handlers: Vec<(gst::Element, glib::SignalHandlerId)>,
        mut output_probe: Option<(gst::Pad, gst::PadProbeId)>,
        caller_registry: Arc<CallerRegistry>,
        bytes_sent: Arc<AtomicU64>,
        callbacks: SrtCallbackContext,
        server_port: u16,
        bind_address: Option<&str>,
        udp_ingest_port: Option<u16>,
    ) -> Result<Self, RestreamBuildFailure> {
        let health = callbacks.health.clone();
        let fault_probe = callbacks.fault_probe.clone();
        let shutdown_requested = callbacks.shutdown_requested.clone();
        let server_instance = callbacks.server_instance;
        let data_generation = callbacks.data_generation;
        health.arm_first_buffer(
            server_instance,
            data_generation,
            tokio::time::Instant::now(),
        );

        if parts.pipeline.set_state(gst::State::Playing).is_err() {
            stop_candidate(
                &parts.pipeline,
                &bus,
                &shutdown_requested,
                &mut signal_handlers,
                &mut output_probe,
                &caller_registry,
            );
            health.end_data_generation(server_instance, data_generation);
            return Err(classify_state_change_failure(bind_address, server_port));
        }

        health.mark_listener_bound(server_instance);
        if udp_ingest_port.is_some() {
            health.report_streaming_without_buffer(
                server_instance,
                data_generation,
                tokio::time::Instant::now(),
            );
        }

        let (bus_thread, bus_done_rx) = match spawn_bus_thread(bus.clone(), callbacks) {
            Ok(thread) => thread,
            Err(failure) => {
                stop_candidate(
                    &parts.pipeline,
                    &bus,
                    &shutdown_requested,
                    &mut signal_handlers,
                    &mut output_probe,
                    &caller_registry,
                );
                health.end_data_generation(server_instance, data_generation);
                return Err(failure);
            }
        };

        log::info!("SRT relay listener started");
        Ok(Self {
            pipeline: parts.pipeline,
            bus,
            _source: parts.source,
            _mux: parts.mux,
            _sink: parts.sink,
            signal_handlers,
            output_probe,
            caller_registry,
            bus_thread: Some(bus_thread),
            bus_done_rx: Some(bus_done_rx),
            shutdown_requested,
            stopped: false,
            server_generation: health.server_generation(),
            server_instance,
            data_generation,
            health,
            fault_probe,
            udp_ingest_port,
            bytes_sent,
            bw_prev: Mutex::new((0, Instant::now())),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_from_rtsp(
        input_url: &str,
        server_port: u16,
        bind_address: Option<&str>,
        username: &str,
        password: &str,
        passphrase: Option<&str>,
        latency_ms: u32,
        stream_id: &str,
        runtime: RestreamRuntimeContext,
    ) -> Result<Self, RestreamBuildFailure> {
        let upstream_ready = runtime
            .upstream_ready
            .clone()
            .ok_or_else(|| configuration_failure("RTSP upstream readiness guard unavailable"))?;
        upstream_ready().map_err(RestreamBuildFailure::configuration)?;
        let signal_ids = preflight_srt_capabilities()?;
        let parts = parse_pipeline(RTSP_PIPELINE_SKELETON)?;
        configure_rtsp_source(&parts.source, input_url, username, password)?;
        let transport =
            super::rtsp_transport::configure(&parts.source, input_url, upstream_ready.clone())
                .map_err(RestreamBuildFailure::configuration)?;
        configure_sink(
            &parts.sink,
            server_port,
            bind_address,
            passphrase,
            latency_ms,
        )?;
        let bus = parts
            .pipeline
            .bus()
            .ok_or_else(|| configuration_failure("SRT relay pipeline has no bus"))?;
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let fault_probe = SrtRuntimeProbe::new();
        let caller_registry = Arc::new(CallerRegistry::new(Some(stream_id)));
        let data_generation = runtime
            .health
            .begin_data_generation(runtime.server_instance)
            .ok_or_else(|| configuration_failure("SRT relay generation is no longer current"))?;
        let callbacks = SrtCallbackContext::new(
            &runtime,
            fault_probe.clone(),
            shutdown_requested.clone(),
            data_generation,
        );
        let mut signal_handlers = vec![(
            parts.source.clone(),
            super::connect_video_only_select_stream(&parts.source),
        )];
        let upstream_callbacks = callbacks.clone();
        signal_handlers.push((
            parts.source.clone(),
            parts.source.connect("before-send", false, move |_| {
                // Disconnecting this handler during teardown drops the owner
                // and closes the listener and every camera connection.
                let _transport_owner = &transport;
                if upstream_callbacks.is_shutdown_requested() {
                    return Some(false.to_value());
                }
                let ready = upstream_ready().is_ok();
                if !ready {
                    upstream_callbacks.emit_fault(
                        RelayFaultKind::GstError,
                        "Camera readiness lost for SRT relay".into(),
                    );
                }
                Some(ready.to_value())
            }),
        ));
        signal_handlers.extend(install_admission_handlers(
            &parts.sink,
            signal_ids,
            caller_registry.clone(),
            callbacks.clone(),
        ));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let output_probe =
            match install_output_probe(&parts.sink, bytes_sent.clone(), callbacks.clone()) {
                Ok(probe) => Some(probe),
                Err(failure) => {
                    disconnect_handlers(&mut signal_handlers);
                    caller_registry.clear();
                    runtime
                        .health
                        .end_data_generation(runtime.server_instance, data_generation);
                    return Err(failure);
                }
            };
        Self::start_prepared(
            parts,
            bus,
            signal_handlers,
            output_probe,
            caller_registry,
            bytes_sent,
            callbacks,
            server_port,
            bind_address,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_from_udp(
        udp_port: u16,
        server_port: u16,
        bind_address: Option<&str>,
        passphrase: Option<&str>,
        latency_ms: u32,
        stream_id: &str,
        runtime: RestreamRuntimeContext,
    ) -> Result<Self, RestreamBuildFailure> {
        let signal_ids = preflight_srt_capabilities()?;
        let parts = parse_pipeline(UDP_PIPELINE_SKELETON)?;
        configure_udp_source(&parts.source, udp_port)?;
        configure_sink(
            &parts.sink,
            server_port,
            bind_address,
            passphrase,
            latency_ms,
        )?;
        let bus = parts
            .pipeline
            .bus()
            .ok_or_else(|| configuration_failure("SRT relay pipeline has no bus"))?;
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let fault_probe = SrtRuntimeProbe::new();
        let caller_registry = Arc::new(CallerRegistry::new(Some(stream_id)));
        let data_generation = runtime
            .health
            .begin_data_generation(runtime.server_instance)
            .ok_or_else(|| configuration_failure("SRT relay generation is no longer current"))?;
        let callbacks = SrtCallbackContext::new(
            &runtime,
            fault_probe.clone(),
            shutdown_requested.clone(),
            data_generation,
        );
        let mut signal_handlers =
            match install_udp_demux_handlers(&parts.pipeline, callbacks.clone()) {
                Ok(handlers) => handlers,
                Err(failure) => {
                    runtime
                        .health
                        .end_data_generation(runtime.server_instance, data_generation);
                    return Err(failure);
                }
            };
        signal_handlers.extend(install_admission_handlers(
            &parts.sink,
            signal_ids,
            caller_registry.clone(),
            callbacks.clone(),
        ));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let output_probe =
            match install_output_probe(&parts.sink, bytes_sent.clone(), callbacks.clone()) {
                Ok(probe) => Some(probe),
                Err(failure) => {
                    disconnect_handlers(&mut signal_handlers);
                    caller_registry.clear();
                    runtime
                        .health
                        .end_data_generation(runtime.server_instance, data_generation);
                    return Err(failure);
                }
            };
        Self::start_prepared(
            parts,
            bus,
            signal_handlers,
            output_probe,
            caller_registry,
            bytes_sent,
            callbacks,
            server_port,
            bind_address,
            Some(udp_port),
        )
    }

    fn begin_shutdown(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        stop_candidate(
            &self.pipeline,
            &self.bus,
            &self.shutdown_requested,
            &mut self.signal_handlers,
            &mut self.output_probe,
            &self.caller_registry,
        );
    }

    pub async fn shutdown(&mut self) {
        self.begin_shutdown();
        let done_rx = self.bus_done_rx.take();
        let handle = self.bus_thread.take();
        let exited = match done_rx {
            Some(receiver) => tokio::time::timeout(BUS_JOIN_TIMEOUT, receiver)
                .await
                .is_ok(),
            None => false,
        };
        if exited {
            if let Some(handle) = handle {
                let _ = tokio::task::spawn_blocking(move || handle.join()).await;
            }
            log::info!("SRT relay bus thread joined");
        } else {
            log::warn!(
                "SRT relay bus thread did not exit within 3s; leaking it instead of hanging stop"
            );
            drop(handle);
        }
        self.caller_registry.clear();
        self.health
            .end_data_generation(self.server_instance, self.data_generation);
    }

    pub fn bandwidth_kbps(&self) -> f64 {
        let now = Instant::now();
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let mut previous = self
            .bw_prev
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (previous_bytes, previous_time) = *previous;
        *previous = (bytes, now);
        calculate_bandwidth_kbps(bytes, previous_bytes, now.duration_since(previous_time))
    }

    pub fn connected_clients(&self) -> u32 {
        self.caller_registry.active_count()
    }

    pub fn client_limit(&self) -> u32 {
        MAX_SRT_CALLERS
    }

    pub fn server_generation(&self) -> u64 {
        self.server_generation
    }

    pub fn fault_probe(&self) -> SrtRuntimeProbe {
        self.fault_probe.clone()
    }

    pub fn loop_alive(&self) -> bool {
        self.health.loop_alive_for(self.server_instance)
    }

    pub fn udp_ingest_port(&self) -> Option<u16> {
        self.udp_ingest_port
    }
}

impl Drop for SrtRestreamer {
    fn drop(&mut self) {
        self.begin_shutdown();
        self.caller_registry.clear();
        self.health
            .end_data_generation(self.server_instance, self.data_generation);
    }
}

#[cfg(test)]
mod tests {
    use super::super::relay::{RelayIngestKind, RestreamBuildFailureKind};
    use super::*;

    fn init_gstreamer() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| gst::init().expect("GStreamer test initialization failed"));
    }

    fn build_ok<T>(result: Result<T, RestreamBuildFailure>) -> T {
        match result {
            Ok(value) => value,
            Err(failure) => panic!("SRT test build failed: {}", failure.error),
        }
    }

    fn runtime(ingest: RelayIngestKind) -> (RestreamRuntimeContext, Arc<RelayRuntimeHealth>) {
        let health = Arc::new(RelayRuntimeHealth::new(41, ingest));
        let server_instance = health.begin_server_instance(false);
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            RestreamRuntimeContext {
                upstream_ready: None,
                health: health.clone(),
                event_tx,
                server_instance,
            },
            health,
        )
    }

    fn unused_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn wait_for_udp_rebind(port: u16) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[test]
    fn pipeline_skeletons_are_constant_and_secret_free() {
        for skeleton in [RTSP_PIPELINE_SKELETON, UDP_PIPELINE_SKELETON] {
            assert!(!skeleton.contains("location="));
            assert!(!skeleton.contains("passphrase="));
            assert!(!skeleton.contains("streamid="));
            assert!(!skeleton.contains("localaddress="));
            assert!(!skeleton.contains("localport="));
            assert!(skeleton.contains("authentication=true"));
            assert!(skeleton.contains("wait-for-connection=false"));
        }
    }

    #[test]
    fn required_srt_callback_abi_is_available() {
        init_gstreamer();
        build_ok(preflight_srt_capabilities());
    }

    #[test]
    fn rtsp_input_requires_camera_readiness_before_building_srt_output() {
        for denied in [false, true] {
            let (mut runtime, health) = runtime(RelayIngestKind::Rtsp);
            if denied {
                runtime.upstream_ready = Some(Arc::new(|| {
                    Err(AppError::Stream("CAM role missing".into()))
                }));
            }
            let result = SrtRestreamer::start_from_rtsp(
                "rtsp://192.0.2.20/live",
                8890,
                Some("127.0.0.1"),
                "",
                "",
                None,
                125,
                "",
                runtime,
            );
            let failure = match result {
                Ok(_) => panic!("unverified camera must not start SRT output"),
                Err(failure) => failure,
            };
            assert_eq!(failure.kind, RestreamBuildFailureKind::Configuration);
            assert!(!health.snapshot().loop_alive);
            assert!(failure.error.to_string().contains(if denied {
                "CAM role missing"
            } else {
                "readiness guard unavailable"
            }));
        }
    }

    #[test]
    fn named_pipeline_parts_and_mux_normalization_are_present() {
        init_gstreamer();
        for skeleton in [RTSP_PIPELINE_SKELETON, UDP_PIPELINE_SKELETON] {
            let parts = build_ok(parse_pipeline(skeleton));
            assert_eq!(parts.mux.property::<i32>("alignment"), 7);
            assert!(parts.pipeline.by_name("parse").is_some());
            assert_eq!(
                parts
                    .pipeline
                    .by_name("parse")
                    .unwrap()
                    .property::<i32>("config-interval"),
                -1
            );
        }
    }

    #[test]
    fn sink_configuration_supports_passwordless_and_aes_128_modes() {
        init_gstreamer();
        let passwordless = build_ok(parse_pipeline(UDP_PIPELINE_SKELETON));
        build_ok(configure_sink(
            &passwordless.sink,
            8_890,
            Some("127.0.0.1"),
            None,
            125,
        ));
        assert_eq!(passwordless.sink.property::<u32>("localport"), 8_890);
        assert_eq!(passwordless.sink.property::<i32>("latency"), 125);
        assert!(passwordless.sink.property::<bool>("authentication"));
        assert!(!passwordless.sink.property::<bool>("wait-for-connection"));

        let encrypted = build_ok(parse_pipeline(UDP_PIPELINE_SKELETON));
        build_ok(configure_sink(
            &encrypted.sink,
            8_891,
            None,
            Some("0123456789"),
            20,
        ));
        assert_eq!(encrypted.sink.property::<u32>("localport"), 8_891);
        assert_eq!(encrypted.sink.property::<i32>("latency"), 20);
        assert_eq!(
            encrypted
                .sink
                .property_value("pbkeylen")
                .transform::<i32>()
                .unwrap()
                .get::<i32>()
                .unwrap(),
            16
        );
    }

    #[test]
    fn probe_byte_count_handles_buffers_lists_and_other_data() {
        init_gstreamer();
        let buffer = gst::PadProbeData::Buffer(gst::Buffer::with_size(256).unwrap());
        assert_eq!(observed_probe_bytes(Some(&buffer)), 256);
        assert!(observed_probe_arrival(Some(&buffer)));

        let mut list = gst::BufferList::new();
        let writable = list.get_mut().unwrap();
        writable.add(gst::Buffer::with_size(100).unwrap());
        writable.add(gst::Buffer::with_size(200).unwrap());
        let list = gst::PadProbeData::BufferList(list);
        assert_eq!(observed_probe_bytes(Some(&list)), 300);
        assert!(observed_probe_arrival(Some(&list)));

        let event = gst::PadProbeData::Event(gst::event::Eos::new());
        assert_eq!(observed_probe_bytes(Some(&event)), 0);
        assert!(!observed_probe_arrival(Some(&event)));
    }

    #[test]
    fn diagnostic_bind_classifies_occupied_and_non_socket_failures() {
        let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        assert_eq!(
            classify_state_change_failure(Some("127.0.0.1"), port).kind,
            RestreamBuildFailureKind::Bind
        );
        drop(occupied);
        assert_eq!(
            classify_state_change_failure(Some("127.0.0.1"), port).kind,
            RestreamBuildFailureKind::Configuration
        );
    }

    #[test]
    fn diagnostic_bind_allows_a_torn_down_candidate_to_release_its_socket() {
        let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            drop(occupied);
        });

        assert_eq!(
            classify_state_change_failure(Some("127.0.0.1"), port).kind,
            RestreamBuildFailureKind::Configuration
        );
        release.join().unwrap();
    }

    #[test]
    fn srt_probe_returns_each_runtime_fault_once() {
        let (runtime, health) = runtime(RelayIngestKind::Rtsp);
        let data_generation = health
            .begin_data_generation(runtime.server_instance)
            .unwrap();
        let probe = SrtRuntimeProbe::new();
        let event = health
            .report_fault(
                runtime.server_instance,
                data_generation,
                RelayFaultKind::Capability,
                "redacted capability fault".into(),
            )
            .unwrap();
        probe.publish(event, &runtime.event_tx);
        assert_eq!(
            probe.poll_fault().unwrap().fault.kind,
            RelayFaultKind::Capability
        );
        assert!(probe.poll_fault().is_none());
    }

    #[tokio::test]
    async fn passwordless_udp_listener_starts_healthy_and_shuts_down_cleanly() {
        init_gstreamer();
        let udp_port = unused_udp_port();
        let mut server_port = unused_udp_port();
        while server_port == udp_port {
            server_port = unused_udp_port();
        }
        let (runtime, health) = runtime(RelayIngestKind::Udp);
        let mut server = build_ok(SrtRestreamer::start_from_udp(
            udp_port,
            server_port,
            Some("127.0.0.1"),
            None,
            125,
            "",
            runtime,
        ));
        assert_eq!(server.connected_clients(), 0);
        assert_eq!(server.client_limit(), MAX_SRT_CALLERS);
        assert!(server.loop_alive());
        assert_eq!(
            health.snapshot().state,
            super::super::relay::RelayState::Streaming
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(server.loop_alive());

        server.shutdown().await;
        assert!(!server.loop_alive());
        assert!(wait_for_udp_rebind(udp_port).await);
        assert!(wait_for_udp_rebind(server_port).await);
    }
}

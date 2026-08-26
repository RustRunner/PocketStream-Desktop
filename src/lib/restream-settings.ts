import type {
  AppSettings,
  InterfaceInfo,
  RestreamProtocol,
  RestreamSettingsUpdate,
  SrtPassphraseUpdate,
  SrtPassphraseView,
} from "./types.ts";

export interface RestreamFormValues {
  enabled: boolean;
  rtspPort: number;
  rtspToken: string;
  srtPort: number;
  srtLatencyMs: number;
  srtStreamId: string;
  srtPassphrase: SrtPassphraseUpdate;
}

export function selectedRestreamBindInterface(
  config: AppSettings,
  protocol: RestreamProtocol = config.restream_protocol
): string {
  return protocol === "srt"
    ? config.srt_server.bind_interface
    : config.rtsp_server.bind_interface;
}

/** Build the one complete backend transaction used by Settings Save. */
export function buildRestreamSettingsUpdate(
  config: AppSettings,
  values: RestreamFormValues
): RestreamSettingsUpdate {
  return {
    enabled: values.enabled,
    rtsp_server: {
      port: values.rtspPort,
      token: values.rtspToken,
      bind_interface: config.rtsp_server.bind_interface,
    },
    srt_server: {
      port: values.srtPort,
      passphrase: values.srtPassphrase,
      latency_ms: values.srtLatencyMs,
      stream_id: values.srtStreamId,
      bind_interface: config.srt_server.bind_interface,
    },
  };
}

/** A bind selection saves canonical values for both sections and changes
 * only the section selected when the user made the explicit selection. */
export function buildRestreamBindUpdate(
  config: AppSettings,
  protocol: RestreamProtocol,
  bindInterface: string
): RestreamSettingsUpdate {
  const update = buildRestreamSettingsUpdate(config, {
    enabled: config.rtsp_server.enabled,
    rtspPort: config.rtsp_server.port,
    rtspToken: config.rtsp_server.token,
    srtPort: config.srt_server.port,
    srtLatencyMs: config.srt_server.latency_ms,
    srtStreamId: config.srt_server.stream_id,
    srtPassphrase: { action: "keep" },
  });
  if (protocol === "srt") {
    update.srt_server.bind_interface = bindInterface;
  } else {
    update.rtsp_server.bind_interface = bindInterface;
  }
  return update;
}

export function resolveSrtPassphraseUpdate(
  current: SrtPassphraseView,
  draft: string,
  dirty: boolean,
  clearConfirmed: boolean
): SrtPassphraseUpdate {
  if (clearConfirmed) return { action: "clear" };
  if (!dirty || (current.state === "available" && current.value === draft)) {
    return { action: "keep" };
  }
  if (current.state === "unencrypted" && draft.length === 0) {
    return { action: "keep" };
  }
  if (draft.length === 0) {
    throw new Error(
      "Enter a replacement SRT passphrase, or save the empty field and confirm passwordless output"
    );
  }
  return { action: "replace", value: draft };
}

export function srtPassphraseClearNeedsConfirmation(
  current: SrtPassphraseView,
  draft: string,
  dirty: boolean,
  clearConfirmed: boolean
): boolean {
  return (
    !clearConfirmed &&
    dirty &&
    draft.length === 0 &&
    current.state !== "unencrypted"
  );
}

/** A selector status is final only after both the committed protocol and the
 * desired state captured at click time are visible. During a live switch the
 * backend intentionally emits a selected-but-stopped intermediate snapshot. */
export function restreamSwitchStatusIsFinal(
  target: RestreamProtocol | null,
  expectedDesired: boolean | null,
  selected: RestreamProtocol,
  desired: boolean
): boolean {
  return target === selected && expectedDesired === desired;
}

export interface RestreamBindOption {
  value: string;
  label: string;
  unavailable: boolean;
}

export function buildRestreamBindOptions(
  interfaces: readonly InterfaceInfo[],
  saved: string
): RestreamBindOption[] {
  const options: RestreamBindOption[] = [
    { value: "", label: "None", unavailable: false },
  ];
  for (const iface of interfaces) {
    const address = iface.ips[0]?.address;
    options.push({
      value: iface.name,
      label: address ? `${iface.name} (${address})` : iface.name,
      unavailable: false,
    });
  }
  if (saved && !interfaces.some((iface) => iface.name === saved)) {
    options.push({
      value: saved,
      label: `${saved} (unavailable)`,
      unavailable: true,
    });
  }
  return options;
}

export interface RestreamBindRequest {
  generation: number;
  protocol: RestreamProtocol;
}

/** Generation plus protocol identity prevents a late RTSP enumeration from
 * painting over SRT (and vice versa), even when both saved values are valid. */
export class RestreamBindRequestGate {
  private generation = 0;

  begin(protocol: RestreamProtocol): RestreamBindRequest {
    return { generation: ++this.generation, protocol };
  }

  isCurrent(request: RestreamBindRequest, protocol: RestreamProtocol): boolean {
    return request.generation === this.generation && request.protocol === protocol;
  }
}

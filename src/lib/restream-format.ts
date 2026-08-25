/** Render one measured output copy and, for fan-out of two or more clients,
 * the explicitly estimated aggregate offered payload rate. */
export function formatRestreamBitrate(kbps: number, clients: number): string {
  const single = Math.max(0, Number.isFinite(kbps) ? kbps : 0);
  const formatted = `${single.toFixed(1)} kbps`;
  return clients >= 2
    ? `${formatted} / ~${(single * clients).toFixed(1)} kbps aggregate`
    : formatted;
}

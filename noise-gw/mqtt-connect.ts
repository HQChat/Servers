/**
 * The client id inside an MQTT CONNECT — for the gateway's logs only.
 *
 * The broker sees every hqn/1 client arriving from the gateway's address, so
 * the gateway is the one place that knows which public IP a client id came
 * from, and it says so in its log. Nothing is DECIDED on this value: EMQX
 * parses the same packet itself and authenticates it. So this is deliberately
 * forgiving of nothing — anything malformed is simply "no id" — and never
 * throws on attacker bytes.
 *
 * MQTT 3.1.1 and 5 both: fixed header 0x10, remaining length, protocol name,
 * level, flags, keepalive, (v5: properties), client id.
 */
export function connectClientId(packet: Buffer): string | null {
  try {
    if (packet.length < 2 || packet[0] !== 0x10) return null;
    let i = 1;
    let len = 0;
    for (let shift = 0; ; shift += 7) {
      if (i >= packet.length || shift > 21) return null;
      const b = packet[i++]!;
      len += (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
    }
    if (i + len > packet.length) return null;
    const nameLen = packet.readUInt16BE(i);
    i += 2 + nameLen;
    const level = packet[i];
    i += 1 + 1 + 2;                       // level, flags, keepalive
    if (level === 5) {
      let propLen = 0;
      for (let shift = 0; ; shift += 7) {
        if (i >= packet.length || shift > 21) return null;
        const b = packet[i++]!;
        propLen += (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
      }
      i += propLen;
    }
    if (i + 2 > packet.length) return null;
    const idLen = packet.readUInt16BE(i);
    i += 2;
    if (i + idLen > packet.length || idLen > 128) return null;
    const id = packet.subarray(i, i + idLen).toString("utf8");
    return /^[0-9a-f]{64}$/.test(id) ? id : null;
  } catch {
    return null;
  }
}

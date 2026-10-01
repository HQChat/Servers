// Which addresses a service binds.
//
// Under compose every service bound all interfaces and Docker decided what was
// published. On a host with no container runtime the process itself has to say
// where it listens: auth, for one, must answer nginx on loopback and the broker's
// hooks on the WireGuard address, and nothing else.
//
// A Node server binds ONE address, so a list means one server per address, all
// sharing the same handler.
//
//   LISTEN_HOST="127.0.0.1,10.200.0.1"  → two servers
//   unset / empty                       → one server on every interface (compose)

import type * as net from "net";

/** Parse a comma-separated host list. Empty means "every interface". */
export function parseHosts(value: string | undefined): (string | undefined)[] {
  const hosts = (value || "")
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean);
  return hosts.length ? hosts : [undefined];
}

/**
 * Start one server per host from `make`, all on `port`. `onListening` runs once
 * per bound address. Returns the servers, so a caller or a test can close them.
 */
export function listenOn(
  make: () => net.Server,
  port: number,
  hosts: (string | undefined)[],
  onListening?: (host: string) => void,
): net.Server[] {
  return hosts.map((host) => {
    const server = make();
    server.listen(port, host, () => onListening?.(host ?? "*"));
    return server;
  });
}

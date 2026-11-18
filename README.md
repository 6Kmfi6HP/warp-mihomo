# warp-mihomo

One container runs mihomo with a TUN. Other containers use `network_mode: "service:warp-mihomo"` and share that network namespace. Linux auto-redirect mark mode captures public egress, including sockets explicitly bound to the namespace address. Loopback, link-local, private, CGNAT, ULA, IPv4 multicast, and the TUN range stay on the container network. Mihomo marks the front's own dials so those sockets still leave through the container NIC.

The pool is one direct MASQUE front plus N exits. Each exit has `dialer-proxy: warp-front`. Round-robin is across exits. A restart reuses `devices.json`, drops generations that are no longer active, and does not enroll again unless the exit count grew.
`WARP_ROTATE` defaults to `1h` (`0` disables it). Each tick enrolls a new front and exits on fresh `162.159.198.x` addresses, dials one new exit, then points `warp-pool` at that generation. The generation becomes active only after that dial. The TUN is not recreated and already-open flows stay on the previous MASQUE sessions. Those sessions are closed only after no consumer chain names their exits; the front transport alone does not keep the generation alive.


```sh
docker compose up --build
docker compose exec app wget -qO- https://1.1.1.1/cdn-cgi/trace
```

`WARP_EXITS` is the exit count, from 1 to 16, default 3. The front is extra. v4 addresses in one colo still collide; v6 is per device. The destination sees the exit, not the front.

`WARP_TUN=0 ./warp-mihomo run` starts without a TUN. Enrollment accepts the Cloudflare terms of service.

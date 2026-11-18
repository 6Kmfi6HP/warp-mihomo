# warp-mihomo

One container runs mihomo with a TUN. Other containers use `network_mode: "service:warp-mihomo"` and share that network namespace, so their traffic enters the TUN.

The pool is one direct MASQUE front plus N exits. Each exit has `dialer-proxy: warp-front`. Round-robin is across exits. A restart reuses `devices.json`; it does not enroll again unless the exit count grew.
`WARP_ROTATE` defaults to `1h` (`0` disables it). Each tick enrolls a new front and exits on fresh `162.159.198.x` addresses, dials one new exit, then points `warp-pool` at that generation. The TUN is not recreated and already-open flows stay on the previous MASQUE sessions. Those sessions are closed only after their connection chains go idle.


```sh
docker compose up --build
docker compose exec app wget -qO- https://1.1.1.1/cdn-cgi/trace
```

`WARP_EXITS` is the exit count, from 1 to 16, default 3. The front is extra. v4 addresses in one colo still collide; v6 is per device. The destination sees the exit, not the front.

`WARP_TUN=0 ./warp-mihomo run` starts without a TUN. Enrollment accepts the Cloudflare terms of service.

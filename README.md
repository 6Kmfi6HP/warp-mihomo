# warp-mihomo

One container runs mihomo with a TUN. Other containers use `network_mode: "service:warp-mihomo"` and share that network namespace. Linux auto-redirect mark mode captures public egress, including sockets explicitly bound to the namespace address. Loopback, link-local, private, CGNAT, ULA, IPv4 multicast, and the TUN range stay on the container network. Mihomo marks the front's own dials so those sockets still leave through the container NIC.

The pool is M direct MASQUE fronts in `warp-front-pool` (generation-scoped during rotation) plus N exits in `warp-pool`. Each exit has `dialer-proxy: warp-front-pool` (or `warp-front-pool-g<N>`). Round-robin is used across both fronts and exits. A restart reuses `devices.json`, drops generations that are no longer active, and does not enroll again unless the front or exit count grew.
`WARP_ROTATE` defaults to `1h` (`0` disables it). Each tick enrolls new fronts and exits on fresh `162.159.198.x` addresses, probes every new front and at least one new exit, then points `warp-pool` at that generation. The generation becomes active only after that dial. The TUN is not recreated and already-open flows stay on the previous MASQUE sessions. Those sessions are closed only after no consumer chain names their exits; the front transport alone does not keep the generation alive.


```sh
docker compose up --build
docker compose exec app wget -qO- https://1.1.1.1/cdn-cgi/trace
```

`WARP_FRONTS` is the front count, from 1 to 16, default 1. `WARP_EXITS` is the exit count, from 1 to 16, default 3. v4 addresses in one colo still collide; v6 is per device. The destination sees the exit, not the front.

`WARP_TUN=0 ./warp-mihomo run` starts without a TUN. Enrollment accepts the Cloudflare terms of service.

Bypass rules (routing selected domains, CIDRs, or mihomo rules via `DIRECT` instead of `warp-pool`) can be configured with `WARP_DIRECT` (comma-separated domains/CIDRs) and/or a YAML file (`WARP_DIRECT_FILE`, defaulting to `<WARP_DATA>/direct.yaml` if present). Domain entries also resolve DNS directly via `1.1.1.1` DoH.

For production Docker Compose setup, configuration options, verification, and troubleshooting, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Release

Versions are annotated or lightweight git tags `vMAJOR.MINOR.PATCH`. A `-rc.1` suffix is a prerelease. Pushing the tag runs the release workflow: tests, a native `linux/amd64` and `linux/arm64` image build, a push to `ghcr.io/6kmfi6hp/warp-mihomo`, then a GitHub Release. `main` publishes the moving tag `edge` and does not move `latest`.

`0.1.2` is that release. `0.1` tracks the newest patch in that minor. `1` tracks the newest stable `v1`; there is no `0` tag while the major is 0. `latest` tracks the newest stable release, not a prerelease and not `edge`. `edge` tracks `main`. `sha-` plus the short commit pins the commit that published `edge` or a version.

`warp-mihomo version` prints the version without the leading `v`, the full commit, and the commit time. A local build that does not pass those build args prints `dev`. The first package pushed to GHCR is private until its visibility is changed.

```sh
git tag v0.1.0
git push origin v0.1.0
```

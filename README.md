# warp-mihomo

One container runs mihomo with a TUN. Other containers use `network_mode: "service:warp-mihomo"` and share that network namespace. Linux auto-redirect mark mode captures public egress, including sockets explicitly bound to the namespace address. Loopback, link-local, private, CGNAT, ULA, IPv4 multicast, and the TUN range stay on the container network. Mihomo marks the front's own dials so those sockets still leave through the container NIC.

The pool runs two protocol-matched tracks into one exit pool `warp-pool`: H3 (`congestion-controller: bbr`, `bbr-profile: standard`) fronts in `warp-front-h3-pool` feeding H3 exits on `162.159.198.1`/`.2` across distinct ports, and H2 (`network: h2`) fronts in `warp-front-h2-pool` feeding H2 exits on `162.159.198.3`–`254`. Round-robin is used across fronts and in `warp-pool`. A restart reuses `devices.json`, drops generations that are no longer active, and does not enroll again unless a track's count grew.
`WARP_ROTATE` defaults to `1h` (`0` disables it). Each tick enrolls new H3 and H2 fronts and exits on fresh endpoints, probes all new fronts (requiring at least one front and one exit per enabled track), then points `warp-pool` at that generation. The generation becomes active only after that dial. The TUN is not recreated and already-open flows stay on the previous MASQUE sessions until idle or past a bounded drain timeout (up to `5m`, or `interval/2`), after which lingering sessions are closed so the next rotation always has free H3 endpoints.


```sh
docker compose up --build
docker compose exec app wget -qO- https://1.1.1.1/cdn-cgi/trace
```

Defaults: `WARP_FRONTS_H3=2`, `WARP_EXITS_H3=3` (`fronts + exits <= 7` so active and rotating generations fit the 14 H3 `IP:Port` pairs on `.1`/`.2`), `WARP_FRONTS_H2=1`, `WARP_EXITS_H2=1` (0 disables either track, as long as one track is enabled). v4 addresses in one colo still collide; v6 is per device. The destination sees the exit, not the front.

`WARP_TUN=0 ./warp-mihomo run` starts without a TUN. Enrollment accepts the Cloudflare terms of service. When the official API answers 429 (rate limit), enrollment falls back to a browser-style registration endpoint (the service behind m2c.pages.dev) by presenting the frontend's `Origin`/`Referer` headers; set `WARP_FALLBACK_REG_URL` to point elsewhere or `WARP_FALLBACK_REG_URL=off` to disable.

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

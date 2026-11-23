# 部署文档

本文档说明如何在生产或测试环境中使用 Docker Compose 部署 `warp-mihomo`，使其作为同网络命名空间内业务容器的透明 WARP 出口网关。

## 1. 架构与工作原理

`warp-mihomo` 在单个容器中运行内置 mihomo 与 TUN 网关，核心数据流如下：

1. **网络共享**：业务容器通过 `network_mode: "service:warp-mihomo"` 共享 `warp-mihomo` 的网络命名空间。
2. **透明劫持**：mihomo 启用 `tun`（`stack: mips`、`auto-route: true`、`auto-redirect: true`），在 Linux 下使用 mark 模式接管容器内的公网出站流量及端口 53 的 DNS 请求（`dns-hijack`）。
3. **直连绕行**：容器内网及保留地址段（`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`、`198.18.0.0/15`、`224.0.0.0/4`、`::/127`、`fc00::/7`、`fe80::/10`）保持直连，不进入 WARP。
4. **单跳池化与轮换**：
   - 池由 1 个直连的 MASQUE 前置节点（`warp-front`）和 N 个出口节点（`warp-exit-*`，通过 `dialer-proxy: warp-front` 建连）组成，`warp-pool` 以 `round-robin` 策略在各出口间轮询。
   - 目标服务器看到的是出口节点的 IP，而非前置节点 IP；同一接入点下 IPv4 仍可能碰撞，IPv6 按设备独立分配。
   - 当启用 `WARP_ROTATE` 时，后台会定期注册新一代节点、探测至少一个新出口连通后原子切换 `warp-pool`。TUN 不会被重建，既有连接继续在旧代会话上自然排空，全部空闲后再清理旧代设备。

---

## 2. 环境要求

- **宿主机系统**：Linux（需内核支持 `/dev/net/tun` 及 `nftables`/`iptables` mark 路由）。
- **容器运行时**：Docker Engine + Docker Compose v2。
- **网络连通性**：宿主机出站需允许访问 Cloudflare WARP 注册接口、MASQUE 服务（`162.159.198.x:443` / `consumer-masque.cloudflareclient.com`）以及 `1.1.1.1:443`。
- **镜像拉取权限**：镜像发布在 `ghcr.io/6kmfi6hp/warp-mihomo`。如果仓库的 GHCR Package 仍为 Private，需先在宿主机执行 `docker login ghcr.io`，或在 GitHub Package 设置中将其改为 Public。

---

## 3. 快速部署（Docker Compose）

新建 `compose.yaml`（生产环境建议固定具体版本标签，例如 `0.1.0` 或跟踪小版本的 `0.1`）：

```yaml
services:
  warp-mihomo:
    image: ghcr.io/6kmfi6hp/warp-mihomo:0.1.0
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      WARP_EXITS: "3"
      WARP_ROTATE: "1h"
      SKIP_SYSTEM_IPV6_CHECK: "1"
    dns:
      - 1.1.1.1
      - 1.0.0.1
    volumes:
      - warp-data:/data
    # 所有业务容器对外暴露的端口都必须写在这里，不能写在业务容器上
    # ports:
    #   - "8080:8080"
    healthcheck:
      test: ["CMD", "warp-mihomo", "health"]
      interval: 30s
      timeout: 20s
      retries: 5
      start_period: 90s
    restart: unless-stopped

  app:
    image: alpine:3.21
    network_mode: "service:warp-mihomo"
    depends_on:
      warp-mihomo:
        condition: service_healthy
    command: ["sleep", "infinity"]
    restart: unless-stopped

volumes:
  warp-data:
```

启动服务：

```sh
docker compose up -d
```

### 关键配置说明

- **`cap_add: [NET_ADMIN]` 与 `/dev/net/tun`**：创建和配置 TUN 接口与路由规则所必需。
- **`dns: [1.1.1.1, 1.0.0.1]`**：必须显式指定公共 DNS，使业务容器的解析请求发往 53 端口从而被 TUN 的 `dns-hijack` 劫持；若不设置，Docker 默认使用 `127.0.0.11`，本地回环流量不会经过 TUN。
- **`volumes: [warp-data:/data]`**：持久化已注册的设备凭证（`devices.json`）与生成配置（`mihomo.yaml`）。重启容器时会复用当前活跃代设备，不会重复向 Cloudflare 注册。
- **`ports` 声明位置**：使用 `network_mode: "service:warp-mihomo"` 的业务容器不能单独声明 `ports`，必须全部配置在 `warp-mihomo` 服务下。
- **使用条款**：首次启动注册设备即代表接受 Cloudflare WARP 服务条款。

---

## 4. 配置参考

### 环境变量

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `WARP_DATA` | `/data`（容器内） / `data`（本地） | 状态与配置文件目录 |
| `WARP_EXITS` | `3` | 出口设备数量，合法范围 `1`–`16`（前置节点额外计 1 个） |
| `WARP_ROTATE` | `1h` | 自动轮换间隔（Go duration 格式，如 `30m`、`2h`）；设为 `0` 关闭轮换 |
| `WARP_TUN` | `true` | 是否启用 TUN；设为 `0`、`false` 或 `no` 可关闭 |
| `SKIP_SYSTEM_IPV6_CHECK` | `1`（容器内） | 跳过系统 IPv6 检查，`run` 启动时若为空也会默认设为 `1` |

### 镜像标签策略

- `0.1.0`：固定到具体发布版本（生产环境推荐）。
- `0.1`：跟踪 `0.1.x` 最新补丁版本。
- `latest`：跟踪最新稳定版（不含预发布版本与 `edge`）。
- `edge`：跟踪 `main` 分支最新构建。
- `sha-<commit>`：固定到某次发布提交的不可变镜像。

### 常用子命令

```sh
# 查看当前镜像版本、提交哈希与构建时间
docker compose exec warp-mihomo warp-mihomo version

# 手动执行一次连通性与 WARP 状态检查
docker compose exec warp-mihomo warp-mihomo health

# 仅预先注册设备到数据目录，不启动代理
docker compose run --rm warp-mihomo enroll -data /data -exits 3
```

---

## 5. 部署验证

1. **查看容器状态与日志**：

```sh
docker compose ps
docker compose logs -f warp-mihomo
```

正常启动后日志会输出类似信息：

```text
mihomo ... devices 4 tun true
rotate every 1h0m0s
```

2. **验证健康检查**：

```sh
docker compose exec warp-mihomo warp-mihomo health
```

预期输出包含 `warp=on ip=<exit_ip>`。

3. **验证业务容器出站流量**：

```sh
docker compose exec app wget -qO- https://1.1.1.1/cdn-cgi/trace
```

确认返回结果中包含 `warp=on`，且多次请求或轮换后出口 IP 来自 Cloudflare WARP。

---

## 6. 日常运维与升级

### 升级镜像

```sh
# 修改 compose.yaml 中的版本标签后执行
docker compose pull warp-mihomo
docker compose up -d
```

### 调整出口数量（`WARP_EXITS`）

- 修改 `WARP_EXITS` 并执行 `docker compose up -d` 即可生效。
- 调大数量时会自动补齐注册缺少的出口设备；调小数量时会复用已有活跃设备。

### 重置设备状态

如需强制重新注册全部设备，可停止服务并清理数据卷中的状态文件后重启：

```sh
docker compose down
docker volume rm <project>_warp-data
docker compose up -d
```

> 注意：`/data` 目录下通过 `devices.lock` 保证同一时间只有一个 `warp-mihomo` 进程操作状态文件，请勿将同一数据卷挂载给多个同时运行的实例。

---

## 7. 常见问题排查

1. **拉取镜像报 `unauthorized` / `denied`**
   - 原因：GHCR 首次推送的镜像包默认为私有。
   - 处理：在 GitHub 仓库右侧 Packages 页面将该包可见性修改为 Public，或在宿主机使用具备 `read:packages` 权限的 Token 执行 `docker login ghcr.io`。

2. **启动报 `/dev/net/tun` 打开失败或权限错误**
   - 原因：宿主机未加载 `tun` 内核模块，或容器缺少 `NET_ADMIN` 权限与设备映射。
   - 处理：在宿主机执行 `sudo modprobe tun` 并确认 `/dev/net/tun` 存在，同时核对 Compose 中的 `cap_add` 与 `devices` 配置。

3. **健康检查一直处于 `starting` 或 `unhealthy`**
   - 原因：首次启动需要向 Cloudflare 注册 `1 + WARP_EXITS` 个设备并探测连通性；或宿主机无法直连 Cloudflare `443` 端口。
   - 处理：查看 `docker compose logs warp-mihomo` 报错详情；确认宿主机防火墙放行 UDP/TCP 出站 `443`，并适当保留 `start_period: 90s`。

4. **业务容器 DNS 解析异常或未走 WARP**
   - 原因：业务容器未正确配置 `network_mode: "service:warp-mihomo"`，或未在 `warp-mihomo` 上配置 `dns: [1.1.1.1, 1.0.0.1]`。
   - 处理：检查业务容器内的 `/etc/resolv.conf` 是否指向 `1.1.1.1` / `1.0.0.1`，而非 `127.0.0.11`。

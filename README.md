# STUN-NAT

独立的 STUN 内网穿透管理系统，按 Lucky 的 STUN 模块工作方式实现：在一台设备上维持 TCP 或 UDP 的 NAT 映射，获得动态公网端口，再将流量转发到指定内网服务，或交由路由器直转。

它不是双节点 P2P 打洞系统，也不提供中继服务。映射是否可用取决于运营商和每一层 NAT 是否为 NAT1（全锥形）。公网端口不可指定，变化周期也无法保证。

## 功能

- Web 管理页面、HTTP Basic Auth 和规则 REST API。
- 多条 IPv4 TCP / UDP 穿透规则。
- 通道监听端口支持固定值或 `0` 随机分配。
- TCP 使用同源端口保活连接和 STUN TCP 探测；UDP 持续保活并周期性探测。
- Lucky 内置转发模式：TCP/UDP 流量转发到 `目标地址:目标端口`。
- bind 直转模式：只建立 NAT 映射；由路由器端口转发直接指向目标设备，可保留真实访问者 IP。
- NAT-PMP 与 UPnP IGD 自动上级路由映射。
- Linux `iptables` 自动放行通道端口（每条规则可选）。
- 每条规则保存动态公网地址、端口、IP4P 地址、本地端口、运行状态和日志。
- 支持将状态文件用于 DDNS：`data/state/<规则 ID>.json`。
- 默认每 10 秒进行一次 STUN/保活心跳；连续缺失心跳会自动重建映射。
- 可选独立公网探针：TCP 验证通道握手，UDP 验证映射引擎健康回显；两者均不依赖目标服务是否启动。
- 映射成功或公网端点变化后，可调用指定 GET 或 POST Webhook；保活心跳不会重复触发。

映射核心使用 [NATMap](https://github.com/heiher/natmap) 的 MIT 许可实现，管理服务、规则存储、路由映射适配和界面为本项目独立编写。

## 部署

此类程序必须运行在需要暴露服务的主路由或内网设备上，Docker 必须使用宿主机网络；容器 NAT 网络会破坏端口映射。

`network_mode: host` 面向 Linux 主机/路由器。Docker Desktop（macOS/Windows）会将 host 网络指向其 Linux VM，管理端口和 NAT 映射均不等同于桌面宿主机；可用于构建验证，但不能替代在目标 Linux 路由设备上的部署。

```sh
export STUNMAP_ADMIN_USER=admin
export STUNMAP_ADMIN_PASSWORD='use-a-long-random-password'
docker compose up -d --build
```

访问 `http://设备地址:16888`，使用上面的账号密码登录。

首次建议创建一条 TCP 内置转发规则：

| 字段 | 示例 |
| --- | --- |
| 穿透类型 | `IPv4 TCP` |
| 通道监听端口 | `0`（随机）或未被占用的高端口 |
| STUN 服务器 | `turn.cloudflare.com:3478` |
| TCP 保活服务器 | `www.cloudflare.com:80` |
| 转发模式 | `Lucky 内置转发` |
| 目标地址 / 端口 | `192.168.1.20` / `443` |

运行后页面会显示 `公网映射 IP:端口`。该端口可能变化，应通过状态文件或后续 DDNS 集成同步域名记录。

## 公网可达性探针

STUN 成功证明映射已建立，但不能单独证明外部入站数据包当前仍可到达。需要严格验证时，将探针部署在与家庭网络不同的公网 VPS：

```sh
export STUNMAP_PROBE_TOKEN='use-a-long-random-token'
docker compose -f docker-compose.probe.yml up -d --build
```

在穿透规则的“定制模式”填写：

```text
公网探针地址: http://<VPS IPv4>:16900/probe
公网探针令牌: 与 STUNMAP_PROBE_TOKEN 相同
公网探针间隔: 10
```

探针不会访问目标内网服务。TCP 只验证公网端口的三次握手；UDP 发送 `SMHP:` 健康报文，映射引擎在转发前原样回显。因此即使 `targetHost:targetPort` 尚未启动，健康结果仍可正确反映 NAT 通道状态。探针连续两次失败时，规则会立即重建映射。

## 映射 Webhook

在规则“定制模式”设置 Webhook 地址和方法。首次获取映射、或 STUN 地址/端口变化时会触发一次；每次正常心跳不会重复调用。Webhook 地址和 POST JSON 模板均可使用变量，写法支持 `{{STUN_PUBLIC_IP}}`、`${STUN_PUBLIC_IP}` 或 `{STUN_PUBLIC_IP}`。

- `POST`：可填写 JSON 模板；为空时发送默认 JSON，包含 `event`、规则信息、STUN 映射、本地通道和路由器映射状态。示例：`{"ip":"{{STUN_PUBLIC_IP}}","port":{{STUN_PUBLIC_PORT}},"address":"{{STUN_PUBLIC_ADDR}}"}`。
- `GET`：URL 中可直接使用变量，并自动补充 `event`、`rule_id`、`rule_name`、`protocol`、`public_address`、`public_port`、`private_address`、`private_port`、`ip4p` 查询参数；URL 中已明确提供的同名参数不会被覆盖。

变量列表：`STUN_PUBLIC_IP`、`STUN_PUBLIC_PORT`、`STUN_PUBLIC_ADDR`、`STUN_PRIVATE_IP`、`STUN_PRIVATE_PORT`、`STUN_PRIVATE_ADDR`、`STUN_IP4P`、`STUN_PROTOCOL`、`STUN_RULE_ID`、`STUN_RULE_NAME`、`STUN_ROUTER_IP`、`STUN_ROUTER_PORT`。JSON 模板中字符串变量应放在双引号内；端口变量可直接作为数值填写。

## 环境要求

1. 光猫拨号时，光猫 DMZ 应指向主路由。
2. 优先在主路由运行。若运行在局域网设备，可启用 NAT-PMP 或 UPnP，或手动将通道监听端口转发到该设备。
3. 放行设备防火墙上的通道监听端口。
4. UDP 规则不支持 bind 直转，必须使用内置转发。
5. TCP bind 直转须在路由器上将通道监听端口转发到目标设备/端口。

## 本地开发与验证

无需安装 npm 依赖：

```sh
STUNMAP_ADMIN_PASSWORD=dev-password npm test
STUNMAP_ADMIN_PASSWORD=dev-password NATMAP_BIN=/path/to/natmap npm start
```

测试覆盖认证、规则校验、创建和删除。真实 NAT 映射测试必须在 NAT1 网络中进行，不能以本机回环结果代替。

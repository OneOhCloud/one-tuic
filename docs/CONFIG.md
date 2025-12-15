# one-tuic 配置示例

## 配置说明

### relay 配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| server | string | 必填 | TUIC 服务器地址 (host:port) |
| uuid | string | 必填 | 用户 UUID |
| password | string | 必填 | 用户密码 |
| udp_relay_mode | string | "native" | UDP 转发模式: "native" (QUIC Datagram) 或 "quic" (QUIC Stream) |
| congestion_control | string | "bbr" | 拥塞控制算法: "bbr", "cubic", "reno" |
| zero_rtt_handshake | bool | false | 是否启用 0-RTT 握手 |
| disable_sni | bool | false | 是否禁用 SNI |
| sni | string | "" | 自定义 SNI 主机名 |
| timeout | string | "8s" | 连接超时时间 |
| heartbeat | string | "3s" | 心跳间隔 |
| skip_cert_verify | bool | false | 是否跳过证书验证（不安全，仅用于测试） |
| alpn | []string | ["h3"] | ALPN 协议列表 |
| send_window | int | 16777216 | 发送窗口大小（字节） |
| receive_window | int | 8388608 | 接收窗口大小（字节） |

### local 配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| server | string | "127.0.0.1:1080" | 本地 SOCKS5 监听地址 |
| username | string | "" | SOCKS5 认证用户名（可选） |
| password | string | "" | SOCKS5 认证密码（可选） |
| dual_stack | bool | null | 是否启用双栈 |
| max_packet_size | int | 1500 | 最大 UDP 包大小 |

## UDP Relay Mode 说明

TUIC 协议支持两种 UDP 转发模式：

### native 模式
- 使用 QUIC Datagram 传输 UDP 数据包
- 延迟更低，适合实时应用
- 需要服务器和网络支持 QUIC Datagram

### quic 模式  
- 使用 QUIC 单向流传输 UDP 数据包
- 兼容性更好，可以穿透更多网络环境
- 适合 Datagram 被阻断的场景

## 配置示例

```json
{
    "relay": {
        "server": "example.com:443",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "password": "your_password_here",
        "udp_relay_mode": "native",
        "congestion_control": "bbr",
        "zero_rtt_handshake": false,
        "disable_sni": false,
        "timeout": "8s",
        "heartbeat": "3s",
        "skip_cert_verify": false,
        "send_window": 16777216,
        "receive_window": 8388608
    },
    "local": {
        "server": "127.0.0.1:1080",
        "max_packet_size": 1500
    },
    "log_level": "info"
}
```

## 使用 quic 模式的配置

```json
{
    "relay": {
        "server": "example.com:443",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "password": "your_password_here",
        "udp_relay_mode": "quic"
    },
    "local": {
        "server": "127.0.0.1:1080"
    },
    "log_level": "info"
}
```

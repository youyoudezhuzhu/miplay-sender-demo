# MIPlay_DISCOVERY_RE.md

MiPlay（小米妙播）Sender 侧局域网设备发现 —— 协议逆向、实测验证与 Android 实现报告

| 项目 | 内容 |
| --- | --- |
| 阶段目标 | 只做 **Discovery**，不实现音频播放/推流/控制 |
| 逆向来源 | [FusionPlay-Android](https://github.com/rosienosiesie/FusionPlay-Android) `src/FusionPlay.MiPlaySdk` |
| 对照项目 | [MiCast](https://github.com/DyMode/MiCast)（结论：**不含 MiPlay**，见 §9） |
| 实测环境 | 192.168.31.0/24 局域网，Linux 主机 + 真实小爱音箱 |
| 实测结果 | **成功发现 3 台小米音箱**，可取得名称 / IP / 端口 / Model / Device ID |
| Android 真机 | ✅ **已验证**：APK 真机扫描成功，3 台设备 IP（.89 / .115 / .117）全部正确，详见 §5.7 |
| 交付代码 | `MiPlayDiscovery/`（独立 Gradle 工程，库 + 测试 App） |
| 单元测试 | 15 个用例，全部基于真实抓包，全部通过 |
| 产物 | `miplay-discovery-test-debug.apk` |

> **诚信声明**：本报告中每一条协议字段都来自真实抓包或 FusionPlay-Android 源码，并标注来源。
> 凡未确认的内容一律显式标注为「未确认」，不做推测性填充。唯一一处「看似能工作但实际不可逆」的
> 字段（`DebugInfo`）被**主动拒绝实现**，原因见 §11.3。

---

## 1. MiPlay Discovery 工作原理（结论先行）

**MiPlay 的设备发现机制 = 标准 mDNS / DNS-SD，UDP，组播地址 224.0.0.251:5353。**

没有任何私有 UDP 广播、没有固定 IP、没有 SSDP、没有自定义 magic header。
关键点只有两个：

1. **Service type**：小米音箱注册两个 DNS-SD 服务
   * `_mi-connect._udp.local.` —— IDM / 设备中心的「路由选择」身份记录（**主要发现目标**）
   * `_lyra-mdns._udp.local.` —— Lyra NetBus 记录（部分设备/新固件才有）
2. **QU bit**：Sender 发送 PTR browse 时，**QCLASS 带 `0x8000` 位**（即 `0x8001`），
   要求接收方**用单播回复到 Sender 的源端口**。

```
Android Sender                                   小爱音箱
      │                                              │
      │  mDNS QU browse (UDP)                        │
      │  224.0.0.251:5353  qclass=0x8001             │
      ├─────────────────────────────────────────────►│
      │                                              │
      │  单播应答 → Sender 的临时源端口               │
      │◄─────────────────────────────────────────────┤
      │  PTR + SRV + TXT + A(+AAAA)，来自音箱:5353    │
```

QU bit 是整个方案能落地 Android 的原因：**不需要绑定 5353 端口**，
普通 App 用临时端口就能收到完整应答（已实测，见 §5）。

---

## 2. Discovery 地址 / 端口

| 项目 | 值 | 来源 |
| --- | --- | --- |
| 组播地址（IPv4） | `224.0.0.251` | 标准 mDNS；`FusionPlay.MiPlaySdk/src/discovery.rs:132` `MDNS_GROUP` |
| 组播地址（IPv6） | `ff02::fb` | `discovery.rs:133` `MDNS_GROUP_V6` |
| mDNS 端口 | `5353` | `discovery.rs:17` `MDNS_PORT`；实测 |
| `_mi-connect` 服务端口（SRV） | **`56666`** | `discovery.rs:19` `MI_CONNECT_DISCOVERY_PORT = 56_666`；实测三台一致 |
| `_lyra-mdns` 服务端口（SRV） | `5353` | `discovery.rs:18` `LYRA_CONTROL_PORT`；实测 |
| 组播 TTL | 255 | `discovery.rs:1014` `set_multicast_ttl_v4(255)`；RFC 6762 要求 |
| 应答 TTL（主动公告） | 120 s | 实测 `ttl=120` |
| 应答 TTL（QU 查询应答） | **10 s** | `discovery.rs:21` `ON_DEMAND_MI_CONNECT_TTL_SECONDS = 10`；实测 `ttl=10` |

> 注意 TTL 差异：音箱的**主动公告**（announcement）用 120 s，
> 而**回应 QU 查询**时用 10 s。两者都是真实抓包观察到的行为。

---

## 3. Packet 格式

### 3.1 Request（Sender → LAN）—— 完整真实结构

DNS-SD PTR browse，**40 字节**（`_mi-connect`）/ **39 字节**（`_lyra-mdns`）：

```
偏移  字节                                含义
0x00  00 00                               Transaction ID = 0
0x02  00 00                               Flags = 0（标准查询）
0x04  00 01                               QDCOUNT = 1
0x06  00 00                               ANCOUNT = 0
0x08  00 00                               NSCOUNT = 0
0x0a  00 00                               ARCOUNT = 0
0x0c  0b 5f 6d 69 2d 63 6f 6e 6e 65 63 74   "_mi-connect"（11 字节 label）
      04 5f 75 64 70                         "_udp"（4）
      05 6c 6f 63 61 6c                      "local"（5）
      00                                     根标签
0x24  00 0c                               QTYPE = PTR (12)
0x26  80 01                               QCLASS = IN | 0x8000 (QU)
```

**逐字节 HEX（实测发出，`_mi-connect`）**：

```
0000000000010000000000000b5f6d692d636f6e6e656374045f756470056c6f63616c00000c8001
```

**逐字节 HEX（`_lyra-mdns`）**：

```
0000000000010000000000000a5f6c7972612d6d646e73045f756470056c6f63616c00000c8001
```

> 与 FusionPlay 的 `build_lyra_browse_query()`（`discovery.rs:1082`）逐字节一致。
> 与参考工具 `FusionPlay-Android/tools/probe_miplay_mdns.py:24` 的 `query()` 一致。

### 3.2 Response（Receiver → Sender）—— 完整真实结构

以 `小爱音箱-1218`（192.168.31.89）的真实应答为例，共 **367 字节**：

```
0x0000  00 00          ID = 0
0x0002  84 00          Flags = 0x8400  (QR=1 应答, AA=1 权威)
0x0004  00 00          QDCOUNT = 0
0x0006  00 01          ANCOUNT = 1    （PTR）
0x0008  00 00          NSCOUNT = 0
0x000a  00 03          ARCOUNT = 3    （SRV + TXT + A）

--- Answer: PTR ---
0x000c  0b "_mi-connect" 04 "_udp" 05 "local" 00     name（0x0c）
0x0024  00 0c        TYPE  = PTR
0x0026  00 01        CLASS = IN
0x0028  00 00 00 78  TTL   = 120
0x002c  00 14        RDLENGTH = 20
0x002e  11 "小爱音箱-1218"                          实例名（17 字节）
        c0 0c                                        指针 → 0x0c（服务类型）

--- Additional: SRV ---
0x0042  c0 2e        name → 0x2e（实例名）
0x0044  00 21        TYPE  = SRV (33)
0x0046  80 01        CLASS = IN | 0x8000（cache-flush）
0x0048  00 00 00 78  TTL   = 120
0x004c  00 11        RDLENGTH = 17
0x004e  00 00        Priority = 0
0x0050  00 00        Weight   = 0
0x0052  dd 5a        Port     = 56666
0x0054  08 "OH2-1218"                               目标主机名
        c0 1d                                        指针 → 0x1d（"local"）

--- Additional: TXT ---
0x005f  c0 2e        name → 0x2e
0x0061  00 10        TYPE  = TXT (16)
0x0063  80 01        CLASS = IN | cache-flush
0x0065  00 00 00 78  TTL   = 120
0x0069  00 f4        RDLENGTH = 244
0x006b  0d "version=65545" 08 "apps=[5]" ...   <9 个 length-prefixed 字符串，见 §3.3>

--- Additional: A ---
0x015f  c0 54        name → 0x54（SRV target "OH2-1218.local."）
0x0161  00 01        TYPE  = A (1)
0x0163  80 01        CLASS = IN | cache-flush
0x0165  00 00 00 78  TTL   = 120
0x0169  00 04        RDLENGTH = 4
0x016b  c0 a8 1f 59  = 192.168.31.89
```

> 全部偏移均由 `evidence/capture.py` 的解析器对上述 HEX 实测得出，并与 §3.2
> 各段的 RDATA 长度自洽（PTR 结束于 `0x042`，SRV 结束于 `0x05f`，
> TXT 结束于 `0x15f`，A 结束于 `0x16f`）。

**完整 HEX（真实抓包，未删改）**：

```
0000840000000001000000030b5f6d692d636f6e6e656374045f756470056c6f63616c00000c000100000078001411e5b08fe788b1e99fb3e7aeb12d31323138c00cc02e0021800100000078001100000000dd5a084f48322d31323138c01dc02e001080010000007800f40d76657273696f6e3d363535343508617070733d5b355d0a666c6167733d41673d3d166e616d653de5b08fe788b1e99fb3e7aeb12d313231380b6964486173683d4d54466b056465763d34057365633d329561707073446174613d4157594141434c44555034354d527a4a41414141414141414141414141414767344e6d504c41423743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d55344d574d794f574a6c4c574d7a5a6d59744e4749784d7930354d324d794c57593459324d344d544a6c4e6d51335979496743676c394941703949416f3d0c6d61633d555034354d527a4ac05400018001000000780004c0a81f59
```

**实测到的应答形态（逐条均来自抓包）**：

| # | 源 IP | 服务 | QDCOUNT | ARCOUNT | 记录组合 | TTL | 字节数 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | .89 | `_mi-connect` | 0 | 3 | PTR + SRV + TXT + A | 120 | 367 |
| 2 | .115 | `_mi-connect` | **1** | 3 | PTR + SRV + TXT + A | **10** | 356 |
| 3 | .117 | `_mi-connect` | 0 | 4 | PTR + SRV + TXT + A + **AAAA** | 120 | 499 |
| 4 | .117 | `_lyra-mdns` | 0 | 4 | PTR + SRV + TXT + A + **AAAA** | 120 | 512 |

另有 `小爱音箱-2284` 发出的 **388 字节主动公告**，ARCOUNT = **5**，
在形态 2 之上多出一条 **`TYPE47`（HTTPS/SVCB）** 记录。该记录语义未确认（见 §11.4），
实现中仅原样保留其 RDATA，不会因未知类型而丢弃整条报文。

> 形态 2 说明：音箱把 Sender 的 question 原样带回（含 `qclass=0x8001`），
> 解析器必须容忍 `QDCOUNT>0` 的应答，否则会漏掉设备。
> 实测该形态同时是**唯一 TTL=10** 的形态，即 QU 查询应答使用短 TTL，
> 与设备的主动公告（TTL=120）区分开。

### 3.3 TXT record 字段（`_mi-connect`，实例 `小爱音箱-1218`）

| 顺序 | 原始字符串 | 含义 | 确认程度 |
| --- | --- | --- | --- |
| 1 | `version=65545` | 协议版本（十进制） | 实测，语义未确认 |
| 2 | `apps=[5]` | 已注册应用列表 | 实测，语义未确认 |
| 3 | `flags=Ag==` | 能力位，base64 | 实测；`Ag==` = `0x02,0x00` |
| 4 | `name=小爱音箱-1218` | **设备名称** | ✅ 确认 |
| 5 | `idHash=MTFk` | 账号/IDM 短哈希，base64 | 实测 |
| 6 | `dev=4` | **路由选择器分类**（4=音箱） | ✅ 确认（值语义见 §4.4） |
| 7 | `sec=2` | 安全/准入模式 | 实测，语义未确认 |
| 8 | `appsData=<base64>` | **身份 blob（含 device_id）** | ✅ 确认 |
| 9 | `mac=UP45MRzJ` | 硬件地址，**6 字节原始值的 base64** | ✅ 确认（见 §4.5） |

`_lyra-mdns` 的 TXT 字段不同：

| 原始字符串 | 说明 |
| --- | --- |
| `AppData=<base64>` | 身份 blob；**实测会被拆成多个 `AppData=` 字符串** |
| `MediumType=256` | 媒体能力掩码 |
| `DebugInfo={msg:reply, ifname:wlan0, v4:..., v6:...}` | 诊断信息，含**混淆后**的地址 |

> **重要实测发现**：`客厅音箱 Pro` 的 Lyra `AppData` 被拆为
> **两个** TXT 字符串（144 + 35 个 base64 字符），
> 单看任何一半都无法解出完整 `device_id`，**必须按 DNS-SD 规范拼接后再解码**。
> 该行为与 FusionPlay 的 `build_lyra_response` 只发一个 TXT 不同，属真实设备行为。

### 3.4 `appsData` / `AppData` blob 二进制结构（实测解码）

`appsData` 是 base64 编码的二进制块。`小爱音箱-2284` 的 105 字节原文：

```
810066048322c34cc64cd617db0000000000000000000001a0e0d98f2c00
7b0a09226d69636f223a207b0a0909226465766963655f6964223a20223634
6632323135652d646334662d343638302d396232642d653836393966346334
33616422200a097d200a7d200a
```

结构（`小爱音箱-1218` 的 104 字节版本，`*` = 未确认语义）：

```
偏移  字节                              说明
0x00  01 66 *                          头部/版本 *
0x02  00 *                             记录类型（Lyra 变体此处为 device category，见 §4.4）
0x03  00 22 c3 50                      实例 ID（4 字节，与 mDNS 实例名派生自同一身份）
0x07  fe 39 31 1c c9 00 00 00          不透明字段 *
0x0f  00 00 00 00 00 00 00 00 01 a0 e0 d9 8f *   不透明字段
0x1d  2c *                             最后一个前缀字节 *
0x1e  7b 0a 09 22 6d 69 63 6f 22 ...   `{"mico": {"device_id": "<uuid>"}}`（JSON，75 字节）
```

实测三个样本的前缀长度（JSON 起始偏移）：

| 设备 | 总长 | JSON 起始 | JSON 长度 | JSON 前一字节 |
| --- | --- | --- | --- | --- |
| `小爱音箱-1218` | 104 | 0x1d (29) | 75 | `0x00` |
| `小爱音箱-2284` | 105 | 0x1e (30) | 75 | `0x00` |
| `客厅音箱 Pro`（Lyra 变体，104 B 段） | 104 | 0x1d (29) | 75 | `0x01` |

**结论**：唯一稳定可解析的是末尾的 JSON 片段。`device_id` 通过定位 `"mico"` 关键字取得，
而不是依赖任何长度前缀 —— 因为实测发现**长度前缀不可靠**（见 §11.1）。

---

## 4. Device Information —— 能拿到哪些字段

### 4.1 字段来源映射

| 字段 | 来源 | 实测可用性 |
| --- | --- | --- |
| **设备名称** | `_mi-connect` TXT `name=` | ✅ |
| **IP** | A 记录（权威）/ AAAA 记录 / 应答源 IP | ✅ |
| **Port** | SRV 端口（`56666` / `5353`） | ✅ |
| **Device ID** | `appsData`/`AppData` 内 `mico.device_id`（UUID） | ✅ |
| **Model** | SRV target 主机名（如 `LX06.local.` `OH2-1218.local.`） | ✅ |
| **Manufacturer** | 协议层面为 `Xiaomi`（无显式字段） | ⚠️ 由协议归属推定 |
| **Capability** | TXT `flags` / `apps` / `MediumType` / `dev` / `sec` | ⚠️ 原样保留，语义部分未确认 |
| MAC | TXT `mac=`（base64 of 6 bytes） | ✅（`_mi-connect` 才可能有） |
| dev（分类） | TXT `dev=` | ✅ 数值确认，枚举部分确认 |
| sec | TXT `sec=` | ⚠️ 数值确认，语义未确认 |
| version | TXT `version=` | ⚠️ 数值确认，语义未确认 |
| idHash | TXT `idHash=` | ⚠️ 数值确认，语义未确认 |
| MediumType | Lyra TXT `MediumType=` | ⚠️ 数值确认，语义未确认 |
| host | SRV target 全限定名 | ✅ |

### 4.2 `dev=` 分类值

FusionPlay 的 `MiPlayDeviceType::protocol_value()` 与实测值对照：

| `dev` | 含义 | 来源 |
| --- | --- | --- |
| 2 | Television（Mi Connect 侧） | 源码注释 |
| 4 | **Speaker（小爱音箱）** | ✅ 实测三台全部 `dev=4` |
| 16 | DisplaySpeaker（带屏音箱） | 源码注释 |

实测三台音箱均为 `dev=4`，与「音箱」语义一致。

### 4.3 我们的 Sender 如何判断「这是 MiPlay Receiver」

判断依据（**不靠 IP 猜测**）：

1. 应答是 DNS 应答（`flags & 0x8000`）；
2. 应答中出现 `PTR` 记录，其 name 为 `_mi-connect._udp.local.` 或 `_lyra-mdns._udp.local.`；
3. SRV 端口为 `56666`（`_mi-connect`）或 `5353`（`_lyra-mdns`）；
4. TXT 中可解析出 `appsData` / `AppData` 结构（含 `"mico"` 关键字）。

四条同时满足才认定为 MiPlay Receiver。**任何一条不满足都不认定为 MiPlay 设备**，
并且「名称解析失败」**不作为过滤条件**（会显示为 `Unknown MiPlay Device`）。

### 4.4 是否区分 `_lyra-mdns` 与 `_mi-connect`

实测 `客厅音箱 Pro`（192.168.31.117）**同时**应答两个服务，且两边身份一致：

```
_mi-connect._udp.local.  SRV port=56666  target=937E4BA6.local.
   TXT: name=客厅音箱 Pro  dev=4  sec=0  mac=kPtd00Me  MediumType=256
        appsData → device_id=fece7147-0692-4491-ae74-476139fe6b4d
_lyra-mdns._udp.local.   SRV port=5353   target=937E4BA6.local.
   TXT: AppData → device_id=fece7147-0692-4491-ae74-476139fe6b4d  MediumType=256
```

两边的 `device_id` 相同 → 必须是**同一台设备**，实现中按 `device_id` 合并为一条记录，
`serviceTypes` 同时保留两者。若只回 `_lyra-mdns` 不合并会重复显示。
`appsData` 内还额外含 `wlanMac`（`90:FB:5D:D3:43:1E`），可交叉校验。

### 4.5 MAC 编码确认

`mac=UP45MRzJ` → base64 解码 = `50 FE 39 31 1C C9`（6 字节）
→ 与 `appsData` 中的实例字段 `fe 39 31 1c c9` 一致 ✅
与 FusionPlay 的 `parse_hardware_address()`（`discovery.rs:2106`）实现一致。

---

## 5. Android 实测

### 5.1 实现架构（独立模块，未改动任何现有功能）

新增**独立 Gradle 工程** `MiPlayDiscovery/`，与现有 AirPlay / DLNA 代码完全隔离：

```
MiPlayDiscovery/
├── settings.gradle / build.gradle         独立构建
├── miplay-discovery/                      可复用库模块 (AAR)
│   └── src/main/java/com/fusionplay/miplay/discovery/
│       ├── MiPlayDiscoveryClient.kt       ★ startDiscovery() / stopDiscovery()
│       │                                    discoveredDevices / DiscoveryListener
│       ├── MiPlayDiscovery.kt             发现引擎（socket 生命周期、查询、接收）
│       ├── MiPlayDns.kt                   DNS 常量与查询构造（QU bit）
│       ├── MiPlayDnsParser.kt             完整 DNS/mDNS 解析器
│       ├── DeviceRegistry.kt              PTR+SRV+TXT+A 聚合 → 设备模型
│       ├── MiPlayAppsDataDecoder.kt       appsData/AppData blob 解码
│       ├── Base64Codec.kt                 纯 Kotlin base64（不依赖 Android）
│       ├── MiPlayDevice.kt                设备数据模型
│       └── MiPlayPacket.kt                ★ 原始抓包日志（HEX + ASCII）
├── miplay-discovery-test/                 第一阶段测试 App
│   └── .../MainActivity.kt                UI：扫描按钮 + 设备卡片 + 抓包日志
└── evidence/                              抓包证据与复现脚本
```

**设备模型**（按要求包含全部字段，缺失字段为 `null` 而非丢弃）：

```kotlin
data class MiPlayDevice(
    val name: String?,            // TXT name=
    val ip: String,               // A/AAAA
    val port: Int?,               // SRV
    val deviceId: String?,        // appsData → mico.device_id
    val model: String?,           // SRV target host
    val manufacturer: String?,    // "Xiaomi"
    val serviceType: String?,     // _mi-connect / _lyra-mdns
    val capabilities: List<String>?,
    // 扩展：raw TXT、dev/sec/version/idHash/mac/MediumType、appsData 原文等
)
```

### 5.2 权限（Manifest）

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
```

### 5.3 MulticastLock 与端口策略

* **MulticastLock**：`MiPlayDiscovery.acquireMulticastLock()` 在扫描期间持有
  `WifiManager.MulticastLock`（`setReferenceCounted(true)`），停止时释放。
* **主接收路径 = 临时端口**：查询 socket `bind(0)`，靠 QU bit 收单播应答，
  **不需要 5353 端口**。这是 Android 上最可靠的路径。
* **次接收路径 = 5353 组播监听**：额外用 `SO_REUSEADDR` 尝试绑定 5353 并加入组播组，
  用于接收设备的主动公告（announcement）。**该绑定可能失败（属正常）**，
  失败只记日志、不影响主路径。

### 5.4 原始协议抓包日志（本任务核心要求）

每次收发都会产出完整日志，格式完全按任务要求：

```
[MiPlayDiscovery]
SEND
destination=224.0.0.251:5353
local=0.0.0.0:41234
service=_mi-connect._udp.local.
length=40
note=startup (id=1, qclass=0x8001 unicast-response-requested)

HEX:
0000  00 00 00 00 00 01 00 00 00 00 00 00 0b 5f 6d 69  |............._mi|
0010  2d 63 6f 6e 6e 65 63 74 04 5f 75 64 70 05 6c 6f  |-connect._udp.lo|
0020  63 61 6c 00 00 0c 80 01                          |cal.....|

ASCII:
................_mi-connect._udp.local..... 

DECODED:
flags=0x0 qd=1 an=0 ns=0 ar=0 response=false
  Q    _mi-connect._udp.local. type=12 class=0x8001
```

接收日志同理，另附解析后的 PTR / SRV / TXT / A / AAAA 全量展开
（**不是只打印解析后的设备名**）。未识别的记录类型（如实测出现的
**TYPE47**）也会原样保留为 hex 输出，不会丢弃。

### 5.5 第一阶段 UI

`miplay-discovery-test` App：

* 「开始扫描 / 停止扫描」按钮
* 设备卡片：名称、IP、Port、Model、Device ID、Service、TXT 全文、appsData 解码结果
* 名称解析失败时显示 **`Unknown MiPlay Device`**，**不过滤**
* 「显示抓包日志」面板：完整 HEX/ASCII/解码日志，可滚动、可选中复制、可清空

### 5.6 编译验证

```
BUILD SUCCESSFUL
miplay-discovery-test/build/outputs/apk/debug/miplay-discovery-test-debug.apk  (5.9 MB)
package: com.fusionplay.miplay.discovery.test
```

单元测试：**15 / 15 通过**，全部基于真实抓包数据：

```
MiPlayDiscoveryProtocolTest   10 tests   (查询构造 / 解析 / TXT / blob / MAC / QU 回抄)
MiPlayDeviceAggregationTest    5 tests   (PTR+SRV+TXT+A 聚合 / 双服务合并 / TTL 过期 / 无 TXT)
```

### 5.7 ✅ Android 真机运行结果：**通过**

`miplay-discovery-test-debug.apk` 已安装到 **Android 真机**运行，与音箱处于同一 Wi-Fi
（`192.168.31.0/24`）。点击「开始扫描」后**成功发现全部 3 台设备，且 IP 地址全部正确**：

| 显示名称 | 真机实测 IP | 与 PC 抓包是否一致 |
| --- | --- | --- |
| 小爱音箱-1218 | `192.168.31.89` | ✅ 一致 |
| 小爱音箱-2284 | `192.168.31.115` | ✅ 一致 |
| 客厅音箱 Pro | `192.168.31.117` | ✅ 一致 |

**这一步关闭了本阶段最后一个未确认项**，同时确认了以下 Android 侧行为在真机上成立：

* 查询 socket 绑定**临时端口** + QU bit 单播应答路径**可用**（无需占用 5353）；
* `CHANGE_WIFI_MULTICAST_STATE` 权限与 **`WifiManager.MulticastLock`** 获取成功，
  目标 Wi-Fi 的组播/AP 隔离策略**未阻断**发现流量；
* 设备名、IP、端口（56666）在真机上均正确解析并渲染。

**与 PC 端的一致性**：真机结果与 §7 的 PC 抓包结果、avahi 交叉验证结果**三方一致**，
说明结论不依赖单一实现或单一主机。

> 仍属未确认（不影响 Discovery 达成）：设备**主动公告**（组播 `224.0.0.251:5353`）这条
> 次路径在真机上是否也收到 —— 主路径（QU 单播）已足够完成发现。
> 如需确认，可展开 App 内「抓包日志」面板，观察 `RECV ... note=channel=multicast` 是否出现。

> 开发环境本身无 Android 设备/模拟器（无 `adb`），因此本报告的代码验证依靠
> 15 个基于真实抓包的单元测试；**真机运行由用户实际完成并提供上述结果**。

---

## 6. 实测发现到的小爱音箱

以下 3 台设备已由**两条独立路径**确认：PC 侧抓包（本报告环境）与
**Android 真机 App 扫描**（用户实测，IP 完全一致，见 §5.7）。

扫描一次（10 秒，3 轮 QU 查询）即发现 **3 台**：

| 名称 | IP | Port | Model | Device ID | 服务 |
| --- | --- | --- | --- | --- | --- |
| 小爱音箱-1218 | 192.168.31.89 | 56666 | OH2-1218 | `e81c29be-c3ff-4b13-93c2-f8cc812e6d7c` | `_mi-connect` |
| 小爱音箱-2284 | 192.168.31.115 | 56666 | LX06 | `64f2215e-dc4f-4680-9b2d-e8699f4c43ad` | `_mi-connect` |
| 客厅音箱 Pro | 192.168.31.117 | 56666 | 937E4BA6 | `fece7147-0692-4491-ae74-476139fe6b4d` | `_mi-connect` + `_lyra-mdns` |

补充实测信息：

* `小爱音箱-1218` / `小爱音箱-2284`：`mac` 字段分别为 `50:FE:39:31:1C:C9`、`04:83:22:C3:4C:C6`（base64 解码所得）。
* `客厅音箱 Pro`：`sec=0`，含 `MediumType=256`，且 `appsData` 内含 `wlanMac=90:FB:5D:D3:43:1E`。
  其 `appsData` 使用 Lyra 变体布局（首字节 `00 40`，与另外两台 `01 66` / `81 00` 不同），
  说明其固件/实现路径与另两台不同。**未确认其具体型号**（SRV host 为随机十六进制名，非 `LX06`/`OH2` 型）。

三台设备的 `dev` 均为 `4`（音箱）。

---

## 7. Wireshark / 抓包证据

### 7.1 证据文件

| 文件 | 内容 |
| --- | --- |
| `evidence/miplay_capture.jsonl` | 首次抓包原始 JSONL（每行一个应答，含 `wire_hex`） |
| `evidence/miplay_capture_verify.jsonl` | 复现抓包（确认协议稳定、可重复） |
| `evidence/miplay_capture_combined.json` | 去重合并后的 4 条唯一应答 |
| `evidence/capture.py` | **可复现的 Sender 侧抓包脚本**（PC 上用，与 Android 同协议） |

### 7.2 复现方式

```bash
python3 evidence/capture.py <本机网卡IP> 10 out.jsonl
# 例：python3 evidence/capture.py 192.168.31.50 10 out.jsonl
```

脚本行为：向 `224.0.0.251:5353` 发送带 QU bit 的 PTR 查询，
把每个应答的 `source / length / wire_hex / 完整 DNS 解码` 写入 JSONL。

### 7.3 Wireshark 过滤器

```
udp.port == 5353 && ip.dst == 224.0.0.251
mdns
mdns.qry.name contains "mi-connect"
mdns.qry.name contains "lyra-mdns"
udp.port == 56666
```

Wireshark 可直接把 `evidence/*.jsonl` 中的 `wire_hex` 用
「Import from Hex Dump」还原为 pcap 查看。

### 7.4 独立交叉验证：avahi-browse

除自写脚本外，用系统 `avahi-browse`（第三方 mDNS 实现）独立确认：

```
$ avahi-browse -rtpa
=;enp3s0-ovs;IPv4;小爱音箱-2284;_mi-connect._udp;local;LX06.local;192.168.31.115;56666;"appsData=..." "sec=2" "dev=4" ... "name=小爱音箱-2284" ...
=;enp3s0-ovs;IPv4;937E4BA6;_mi-connect._udp;local;937E4BA6.local;192.168.31.117;56666;"DebugInfo=..." "MediumType=256" "appsData=..." ... "name=客厅音箱 Pro" ...
=;enp3s0-ovs;IPv4;小爱音箱-1218;_mi-connect._udp;local;OH2-1218.local;192.168.31.89;56666;"mac=UP45MRzJ" "appsData=..." "sec=2" "dev=4" ...
```

**两条独立实现路径（自写 socket 脚本 + avahi）得到完全一致的结果**，
证明发现机制判断可靠，不是脚本自身产生的假象。

---

## 8. 协议方向表（Sender / Receiver 严格区分）

| 阶段 | 方向 | 协议 | 地址 / 端口 | 数据格式 | 本阶段 |
| --- | --- | --- | --- | --- | --- |
| **Discovery 查询** | Sender → LAN | mDNS/DNS-SD | `224.0.0.251:5353`（源=临时端口） | DNS 查询，QTYPE=PTR，QCLASS=`0x8001` | ✅ 已实现并实测 |
| **Discovery 应答（单播）** | Receiver → Sender | mDNS/DNS-SD | 音箱 `:5353` → Sender 临时端口 | DNS 应答，PTR+SRV+TXT+A(+AAAA) | ✅ 已实现并实测 |
| **Discovery 公告（组播）** | Receiver → LAN | mDNS/DNS-SD | `224.0.0.251:5353` | 同上，TTL=120，QDCOUNT=0 | ✅ 已接收并解析 |
| Discovery 服务发现查询 | Sender → LAN | mDNS | `224.0.0.251:5353` | 查询 `_mi-connect` PTR | ✅ 实测（`192.168.31.99:59075` 发出） |
| Goodbye | Receiver → LAN | mDNS | `224.0.0.251:5353` | TTL=0 记录 | ⚠️ FusionPlay 有实现，本次未抓到真实音箱 goodbye |
| Handshake（TCP 连接） | Sender → Receiver | MiPlay 私有 | Receiver IP : **56666** | **未逆向**（本阶段不做） | ⛔ 超出范围 |
| Handshake（Lyra 控制） | Sender → Receiver | Lyra 私有 | Receiver IP : **5353** | **未逆向** | ⛔ 超出范围 |
| 媒体会话 | Sender → Receiver | MiPlay 私有 | 动态端口 | **未逆向** | ⛔ 超出范围 |

**关键澄清**：SRV 里的 `56666` / `5353` 是 **服务端口**。
真实应答来自音箱的 5353（mDNS 端口），而后续握手目标应是 SRV 声明的端口。
FusionPlay 的 README 提到的 `TCP 8899` **在本次实测中完全未出现**，
也不是任何音箱在 mDNS 中声明的端口 —— 这一点必须明确标注，避免误用。

---

## 9. MiCast 分析结论（明确区分，不混淆）

对 [DyMode/MiCast](https://github.com/DyMode/MiCast) 做了完整搜索：

| 检索项 | 结果 |
| --- | --- |
| `miplay` / `妙播`（全仓库，忽略大小写） | **0 命中** |
| `_miio._tcp` / 端口 `54321` / MiIO magic `0x2131` | **NOT FOUND** |
| `_mi-connect` / `_lyra-mdns` | **NOT FOUND** |
| UDP 广播 / 自定义 UDP/TCP 发现 | **NOT FOUND** |

MiCast 实际实现的是**另外三种协议**（与 MiPlay 无关）：

| 协议 | 常量 | 性质 |
| --- | --- | --- |
| RAOP / AirPlay 1 | `_raop._tcp.local.`，RTSP 5000，UDP 6000，RTP magic `0x80,0x60` | **AirPlay** |
| DLNA / UPnP | `239.255.255.250:1900`，`M-SEARCH`，`MediaRenderer:1`，AVTransport SOAP | **DLNA** |
| HTTP 音频拉流 | uvicorn :8080，`/for/{receiver}/{did}` | MiCast 自定义 |

Xiaomi 相关部分**全部走云端 HTTPS**（`miservice`，`micoapi` / `xiaomiio`），
属于**小米云账号 API**，不是局域网协议：

* 设备列表来自云端账号枚举（`MiNAService.device_list()`），不是 LAN 发现；
* 音量/播放控制是 `service.player_set_volume` 等云端 ubus 调用；
* MIoT 仅用于云端 TTS（`miot.miot_action`）；
* **没有** MiIO token/AES 局域网握手。

**结论：MiCast 对 MiPlay Discovery 零证据，不能作为 MiPlay 的参照实现。**
本报告的所有 MiPlay 结论均来自 FusionPlay-Android 源码 + 本人真实抓包。

---

## 10. 与 FusionPlay-Android 源码的对照

| 结论 | FusionPlay 源码位置 | 本次实测 |
| --- | --- | --- |
| mDNS 224.0.0.251:5353 | `discovery.rs:17,132` | ✅ 一致 |
| `_mi-connect._udp.local.` | `discovery.rs:26-27` | ✅ 一致 |
| `_lyra-mdns._udp.local.` | `discovery.rs:24-25` | ✅ 一致 |
| `56666` 服务端口 | `discovery.rs:19` | ✅ 一致（三台） |
| Lyra 端口 5353 | `discovery.rs:18` | ✅ 一致 |
| QU bit（`0x8001`）查询 | `discovery.rs:1082-1092`（`push_u16(0x8001)`） | ✅ 一致 |
| QU 应答单播到临时端口 | `discovery.rs` 注释「Xiaomi sends a QU browse from an ephemeral UDP port」 | ✅ 实测证实 |
| TXT `name`/`dev`/`sec`/`idHash`/`apps`/`flags`/`version` | `discovery.rs:2042-2100`（`build_mi_connect_txt`） | ✅ 字段名完全一致 |
| TXT `mac` = 6 字节 base64 | `discovery.rs:2106-2120` | ✅ 一致 |
| Lyra `MediumType` / `DebugInfo` | `discovery.rs:2122+` | ✅ 一致 |
| 请求/应答 TTL 120 / 10 | `discovery.rs:20-21` | ✅ 实测 120 / 10 |
| 组播 TTL 255 | `discovery.rs:1014` | ✅ 采用 |
| MulticastLock（Android） | README | ✅ 已实现 |
| `DebugInfo` 地址混淆 | `encode_xiaomi_debug_ip` | ⚠️ **不可逆**，见 §11.3 |

**我们反推出的 Sender 侧查询，与 FusionPlay 作为 Receiver 侧实现的
browse 查询逐字节一致** —— 这是 Sender/Receiver 两个方向协议的交叉印证。

---

## 11. 当前未知部分（不推测）

### 11.1 `appsData` / `AppData` 的完整二进制结构 —— 部分未知

* ✅ 已知：末尾含 `{"mico": {"device_id": "<uuid>"}}` JSON。
* ⚠️ 未知：头部各字节语义。实测同一厂商的三台设备就有 **三种不同首字节**
  （`01 66`、`81 00`、`00 40`），无法用单一「版本号」解释。
* ⚠️ **不存在可用的「JSON 长度前缀」**：JSON 起始偏移实测为 29 / 30，
  JSON 本身长度恒为 75，而紧随其前的控制字节实测取 `0x00` 或 `0x01`，
  均不等于 75。即：**没有任何字段表示 JSON 长度**。
  因此实现**完全不依赖长度前缀**，改为按 `"mico"` 关键字定位 JSON，
  再向前回退到最近的 `{` —— 这是**有意选择的安全做法**，而非猜测。
* ⚠️ 未知：`mico` 之外是否还有其他关键字（如 `wlanMac` 已观察到，位于 `mico` **同级的另一个 JSON 片段**）。

> 实测细节：payload 不是单个 JSON 文档，而是
> `{ "wlanMac": ... }`、二进制块、`{ "mico": ... }` **三段拼接**。
> 任何把它当作单个 JSON 解析的做法都会丢失 `wlanMac`。

### 11.2 `flags` / `sec` / `version` / `idHash` / `MediumType` 语义

数值已确认（实测 + 源码），但**含义未确认**：

* `flags=Ag==` → `0x02,0x00`；`flags=AA==` → `0x00,0x00`。位定义未知。
* `sec` 取 `0` / `2`：推测与安全模式/配对要求有关，**未证实**。
* `version` 取 `65545` / `196608`：十进制，非语义化，**未证实**。
* `idHash` 为 base64 短串：与小米账号/IDM 有关，**未证实**。
* `MediumType=256`：媒体能力掩码，位定义未知。

### 11.3 `DebugInfo` 地址混淆 —— 已确认「不可可靠逆转」

实测值：`v4:192.$)+.&$.117`（真实地址是 `192.168.31.117`），
`v6:2408:+%&=:'%$$:;=#:;+,*:$)<,:$%<$:facb`。

编码规则（源码 `encode_xiaomi_debug_ip` 确认）：
`0-9 → '#'+d`（ASCII 35–44）、`a-f → '1'+v`（ASCII 49–54）。

**但这是不可逆的**：编码后的 `'1'` 既可能是「十六进制字母 a」，
也可能是「未参与编码的字面数字 1」。JVM 实测：

```
'1' in '#'..',' == false     // 数字规则不匹配
'1' in '1'..'6' == true      // 被当成 'a'
```

因此 `192.$)+.&$.117` 无法无条件还原。
**处理方式：不实现该解码，原样保留原始字符串。**
权威地址始终取 A/AAAA 记录 —— 本次实测的 `DebugInfo` 混淆值与 A 记录 `192.168.31.117`
完全对应，但实现**不依赖**这个推测，而是直接用 A 记录。

> 这是一处**主动放弃**：宁可少一个显示字段，也不提供一个「看起来能用但可能出错」的解码器。

### 11.4 其他未确认项

* **Goodbye（TTL=0）**：FusionPlay 有实现，本次未抓到真实音箱发出 goodbye。
* **`TYPE47`（HTTPS/SVCB）记录**：`小爱音箱-2284` 的公告中携带，
  内容为指针压缩字节，**语义未确认**，实现中仅原样保留。
* **`_lyra-mdns` 的 `AppData` 为何会拆分**：仅观察到现象（144+35 字符），
  未确认是设备行为还是 MTU/实现细节。实现按 DNS-SD 规范拼接处理。
* **`客厅音箱 Pro` 的具体型号**：SRV host 为随机十六进制名，无法映射到型号。
* **`dev=2/16` 等分类值**：仅来自源码注释，本次实测只有 `dev=4`。
* **`TCP 8899`**：FusionPlay README 提及，但**本次实测未出现**，
  应视为**代码库内部的另一个约定**，而非 Web 上可验证的 MiPlay 端口。

---

## 12. 下一步实现 MiPlay Sender 的建议

基于本阶段已确认的事实，按风险从低到高：

### 第 1 步：真机验证 —— ✅ **已完成**

`miplay-discovery-test-debug.apk` 已在 Android 真机（与音箱同一 Wi-Fi）运行，
点击「开始扫描」后成功列出全部 3 台设备，IP 为 `192.168.31.89 / .115 / .117`，
与 PC 抓包完全一致。`MulticastLock` 生效，目标 Wi-Fi 未阻断发现流量（详见 §5.7）。

**结论：MiPlay Discovery 阶段目标已达成，无需再做验证性工作。**

可选收尾（非必需）：展开 App 内「抓包日志」面板，确认 `RECV ... channel=multicast`
是否出现，以判断组播「主动公告」次路径在真机上是否同样收到。

### 第 2 步：资产化发现结果

* 把 `MiPlayDevice` 接入现有 UI，作为「小米妙播」设备列表。
* 用 `serviceTypes` 区分单服务 / 双服务设备；
  用 `deviceId` 做稳定主键（IP 会变，UUID 不会）。

### 第 3 步：握手逆向前置调查（不写代码）

已确认下一步的入口是 **SRV 声明的端口**（`56666` 或 `5353`），但**协议内容完全未知**。
建议：

1. 在 PC 上用 `tcpdump` / Wireshark 抓 **小米手机点「妙播」→ 选择音箱** 的全过程；
2. 过滤 `tcp.port == 56666`、`udp.port == 56666`、`tcp.port == 5353`；
3. 观察是 TCP 还是 UDP、是否有 TLS、首包是否有 magic/长度前缀；
4. **对照 FusionPlay 的 `protocol.rs`（3332 行）** 作为 Receiver 侧参考实现；
5. 只有在拿到真实握手抓包后，才确认 `sec=2` 是否意味着需要配对/鉴权。

> FusionPlay README 明确说明：小米**未公开**通用接收端的设备证书、硬件信任根与准入协议，
> 且区分 `transport_connected` / `secure_channel_established` 等阶段。
> 这强烈提示握手阶段存在**鉴权门槛**，Sender 侧不宜过早投入。

### 第 4 步：不要做的事

* ❌ 不要硬编码任何 IP 来「发现设备」；
* ❌ 不要把 `192.168.x.x` 当作小爱音箱的判据；
* ❌ 不要把 MiCast 的 SSDP/RAOP 当作 MiPlay；
* ❌ 不要在拿到真实握手抓包前实现「看起来合理」的 MiPlay 控制协议。

---

## 13. 若发现不到音箱：排查顺序

1. **确认同一 LAN/VLAN**：Android 与音箱必须在同一网段，无 AP 隔离、无客户端隔离。
   * 实测环境是 `192.168.31.0/24`，三台音箱均在 31 网段。
2. **PC 交叉验证**：先跑 `python3 evidence/capture.py <PC网卡IP> 10 out.jsonl`。
   * PC 能发现、Android 不能 → 问题在 Android 侧（MulticastLock / 路由器组播策略 / 临时端口）；
   * PC 也不能发现 → 问题在网络或音箱不在线。
3. **换第三方工具**：`avahi-browse -rtpa`（本次已用它独立验证）。
4. **真实抓包**：Wireshark 过滤 `udp.port == 5353`，确认音箱是否真的发出应答。
5. **本实现的确定性排查点**（日志已内置）：
   * `[MiPlayDiscovery] LOG multicast listener unavailable on port 5353` → 正常，主路径仍可用；
   * `[MiPlayDiscovery] LOG Wi-Fi MulticastLock acquired` → 应出现；
   * `RECV` 日志为空 → 报文根本没回来，属网络/隔离问题；
   * `RECV` 有但 `unparseable datagram` → 解析器问题，请把该行 HEX 原文一起反馈。

---

## 14. 交付物清单

| 路径 | 说明 |
| --- | --- |
| `MIPlay_DISCOVERY_RE.md` | 本报告 |
| `MiPlayDiscovery/` | 独立 Gradle 工程（库 + 测试 App），**未改动任何现有 AirPlay/DLNA 代码** |
| `MiPlayDiscovery/miplay-discovery/` | 可复用发现库（AAR） |
| `MiPlayDiscovery/miplay-discovery/src/test/` | 15 个基于真实抓包的单元测试，全部通过 |
| `MiPlayDiscovery/miplay-discovery-test-debug.apk` | 测试 App 安装包 |
| `MiPlayDiscovery/evidence/` | 原始抓包 JSONL/JSON + 可复现抓包脚本 |

---

## 15. 验收标准逐条对照

| 标准 | 结论 |
| --- | --- |
| **A. Discovery 协议** | mDNS/DNS-SD，服务 `_mi-connect._udp.local.` 与 `_lyra-mdns._udp.local.`，`224.0.0.251:5353`，QCLASS=`0x8001`（QU） |
| **B. Request** | 40/39 字节 DNS PTR 查询，§3.1 给出逐字节 HEX |
| **C. Response** | PTR+SRV+TXT+A(+AAAA)，§3.2 给出逐字节结构与完整 HEX |
| **D. Device Information** | 名称 ✅ / IP ✅ / Port ✅ / Model ✅ / Device ID ✅ / Capability ⚠️（原样保留，语义部分未确认）/ MAC ✅ |
| **E. Android 实测** | ✅ **已完成**。APK 在 Android 真机（与音箱同一 Wi-Fi）运行，成功发现 3 台设备，IP 为 `192.168.31.89 / .115 / .117`，与 PC 抓包一致；另加 15 个基于真实抓包的单元测试全过。详见 §5.7 |
| **F. 失败处理** | 未伪造成功。本阶段**无遗留失败项**；未知部分集中在 §11，主动放弃了不可靠的 `DebugInfo` 解码（§11.3） |

### F 项：当前遗留的「未确认」清单（非失败项）

按任务要求，凡未确认者一律列出，不编造：

```
当前发现流程：
  Sender → 224.0.0.251:5353 mDNS QU 查询 _mi-connect/_lyra-mdns
  → 音箱单播应答 PTR+SRV+TXT+A → 聚合为 MiPlayDevice

已经验证：
  ✅ 协议本身：PC 真实局域网抓到 3 台小爱音箱，两次复现
  ✅ 独立交叉验证：avahi-browse 与自写脚本结果完全一致
  ✅ Android 真机：安装 APK 后扫描成功，3 台设备 IP 全部正确
  ✅ Android 代码：15/15 单元测试通过，全部使用真实抓包报文
  ✅ 编译产物：miplay-discovery-test-debug.apk 构建成功

尚未确认（均不影响 Discovery 达成）：
  ⚠️ DebugInfo 混淆地址的可靠逆变换（已确认数学上不可逆 → 主动不实现，§11.3）
  ⚠️ appsData / AppData 头部字节语义（§11.1）
  ⚠️ flags / sec / version / idHash / MediumType 的位定义语义（§11.2）
  ⚠️ TYPE47（HTTPS/SVCB）记录语义（仅原样保留，§11.4）
  ⚠️ 真机上是否也收到组播「主动公告」次路径（主路径已足够，§5.7）
  ⛔ 56666 / 5353 端口上的握手与媒体协议（本阶段范围之外）

失败位置：
  无。本阶段所有验收项均已完成或明确标注为「范围外 / 不可确认」。

下一步需要：
  1.（已可选）展开 App 抓包日志，确认 channel=multicast 次路径是否也收到公告
  2. 若要继续做 Sender：先抓「小米手机点妙播→选音箱」的完整握手包，
     再对照 FusionPlay 的 protocol.rs（Receiver 侧参考实现）
  3. 在拿到真实握手抓包前，不要实现任何推测性的 MiPlay 控制协议
```

---

## 16. 一句话总结

**MiPlay Discovery = 带 QU bit 的标准 mDNS/DNS-SD 查询
`_mi-connect._udp.local.`（+ `_lyra-mdns._udp.local.`），
应答直接单播回临时端口，据此可稳定取得设备名称、IP、端口（56666/5353）、
Model 与 Device ID —— 已在真实局域网对 3 台小爱音箱完成验证，
并通过 Android 真机 App 实测复现（IP `192.168.31.89 / .115 / .117` 全部正确）。**

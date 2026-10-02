# MiPlay 音频推流协议（WFD/RTSP）—— 实测还原

> 依据：`/tmp/mp/aud/full.pcap`（真实播放会话，5.28 MB）中两条 RTSP 连接的完整对话，
> 以及同期的 MPEG-TS 音频流。所有内容均为**实测**，不是推测。

---

## 0. 关键结论：方向是反的

```
音箱 (10.42.0.127) ──TCP 拨号──> 平板 (10.42.0.42) : <RTSP 端口>
                                          ▲
                                          │  平板必须自己当 RTSP/WFD 服务器
                                          │
                              wfd://10.42.0.42:<port>?mirrorMode=1
```

平板在**控制通道**里把 `wfd://<自己的IP>:<端口>` 发给音箱（明文可读，见 V4 §3.3），
音箱再**反向拨入**。所以：

* **发送端必须监听一个 TCP 端口**并实现 RTSP 服务端；
* 音频**不是**从第三方主机推的 —— 任何外部主机都无法发起（这就是为什么从 NAS 做不到）。

---

## 1. 两条 RTSP 连接

实测同时存在两条 RTSP 连接，角色不同：

| 流 | 对端 | 用途 |
| --- | --- | --- |
| stream 1 | 音箱 `:52206` ↔ 平板 `:40019` | **音频会话**：`VIDEO_LATENCY` 反馈 + `GET_PARAMETER` 心跳 |
| stream 3 | 音箱 `:49310` ↔ 平板 `:39613` | **能力协商**：`OPTIONS` / `GET_PARAMETER` / `SET_PARAMETER` |

---

## 2. 能力协商（stream 3）

### 2.1 平板 → 音箱：`OPTIONS`

```
OPTIONS * RTSP/1.0
CSeq: 1
Require: org.wfa.wfd1.0
wfd_timer_server_port:170524714:56417
lib_version: audio-display-release2.1 2.1.4111518
authMsg:fcb9521c17e994e450fa59963d45f0e8
authKeyType:3
authAlgorithmTypes:7
```

### 2.2 音箱 → 平板：`200 OK`（带鉴权应答）

```
RTSP/1.0 200 OK
CSeq: 1
Public: org.wfa.wfd1.0, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER
authMsgAck:cab7a6f7a35f9caa0ac8bd631df85319753c32e119d4adbe4ae30853efb76482
```

### 2.3 音箱 → 平板：`GET_PARAMETER`（索取能力）

```
GET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0
CSeq: 2
Content-Type: text/parameters
Content-Length: 299

wfd_content_SP_protection
wfd_video_formats
wfd_video_enctype
wfd_video_gamuttype
wfd_video_bitrate
wfd_dynamic_video_enable
wfd_current_video_info
wfd_audio_codecs_v2
wfd_client_rtp_ports
wfd_tcp_enable
wfd_tcp_multi_session_enable
wfd_support_secure_win
wfd_standby_resume_capability
```

### 2.4 平板 → 音箱：`200 OK` ★ 关键能力声明

```
RTSP/1.0 200 OK
CSeq: 2
Content-Type: text/parameters
Content-Length: 400

wfd_audio_codecs_v2: 63 3 3          ← 声明支持的音频编码
wfd_video_formats: none              ← 纯音频，无视频
wfd_video_enctype: none
wfd_video_gamuttype: none
wfd_video_bitrate: none
wfd_current_video_info: none
wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play
miplay_support_image: none
wfd_standby_resume_capability: supported
wfd_content_SP_protection: 4 1 256 2 1 1 0 0
wfd_support_secure_win:enable
device_info: -1 -1 -1 -1 -1 -1 -1
```

★ **`wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play`**
—— 明确要求 **RTP over TCP 交织模式**，不是 UDP。这决定了传输方式。

### 2.5 音箱 → 平板：`SET_PARAMETER`（选定参数）

```
SET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0
CSeq: 3
Content-Type: text/parameters
Content-Length: 175

wfd_type_encryp: 4 1 1 0 0
wfd_audio_codecs_v2: 1 1              ← 选定 audio codec
wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play
wfd_presentation_URL: rtsp://10.42.0.42/wfd1.0/streamid=0 none
```

★ **`wfd_presentation_URL: rtsp://10.42.0.42/wfd1.0/streamid=0`**
—— 音箱告知它将要拨入的地址。

### 2.6 会话建立后

```
Session: 719885386;timeout=20           ← 会话 ID
GET_PARAMETER ... Session: 719885386    ← 每 10s 一次保活
```

---

## 3. 音频会话（stream 1）

* 平板周期发送 `VIDEO_LATENCY rtsp://localhost/wfd1.0`，带
  `latency` / `bitrate` / `rtpPacketNum` 三个统计量；
* 音箱回 `RTSP/1.0 200 OK` + `Session`；
* **音频数据在同一条 TCP 连接上以 RTSP 交织帧承载**（见 §4）。

---

## 4. 音频帧封装（实测）

### 4.1 外层：RTSP 交织帧

```
'$'(0x24) | 通道:u8 | 长度:u16be | <载荷>
```

★ 注意：**V2 §3.5 记的 `'$' | length:u16be` 是错的**。
实测 `24 00 02 fc` 是 `'$' | 通道=0x00 | 长度=0x02fc`，
即 **`24 00 02 fc` = 通道 0、长度 764**，下一帧在 `4 + 764 = 768`。

**验证结果（对 3,095,052 字节的完整音频流）**：

```
frames = 3502
consumed = 3095052 / 3095052  (100.00%)
resync events = 0
channels = { 0: 3502 }          ← 全部走通道 0
lengths  = 764×2208, 1328×673, 952×449, 200×123, 1140×39, 388×10
```

**100% 消费、零次重新同步** —— 这排除了"两种读法恰好都自洽"的巧合：
按 RTSP 交织帧读，每一个字节都被恰好解释一次。

> 为什么容易读错：`24 00 02 fc` 若按 `'$'|u16be` 读会得到长度 2，立刻脱轨；
> 若按 3 字节 BE 读会得到 0x0002fc = 764 —— 数值恰好也对。
> 但 **`'$'|通道:u8|长度:u16be` 才是 RTSP 标准布局**，且是唯一能解释
> "通道字节恒为 0"的读法（3 字节读法无端多出一个字节）。

### 4.2 交织帧载荷 = 12 字节私有头 + MPEG-TS

```
80 a1 <seq:u16be> <unk:u16be> | de ad be ef | <subtype:u16be> | <MPEG-TS>
 ↑                                                    ↑
 载荷 offset 0                                    offset 12 起是 TS
```

* `80 a1`：固定（100%）
* `seq`：载荷 offset 2-3，逐帧 +1
* `deadbeef`：固定魔数，载荷 offset 8-11（100%）
* `subtype`：载荷 offset 12-13，取值 `4751` / `4740` / `4711`
* ★ 载荷 offset **12** 起是**整段 MPEG-TS**（188 字节/包）。
  **注意 `0x47` 从 offset 12 开始，而不是 0** —— 早期分析曾把
  `47 51` 误读为 TS 头，实际那 12 字节是私有头。

**帧内绝对偏移**（加上 4 字节交织头）：

```
[] 0x24  [] 通道  [][ ] 长度  | 80 a1 seq __ __ __ __ | de ad be ef | subtype | TS...
  帧 0-3 (交织头)              载荷 0..11 (私有头)                载荷 12.. (TS)
```

### 4.3 MPEG-TS 结构（实测）

| PID | 内容 | 说明 |
| --- | --- | --- |
| `0x0000` | PAT | 程序关联表 |
| `0x0100` | PMT | 程序映射表 |
| `0x1000` | PCR | 时钟参考 |
| **`0x1100`** | **PES 音频** | 唯一媒体数据 |

PID `0x1100` 的载荷是标准 PES：

```
00 00 01 c0   PES start code + stream_id=0xc0
02 bc         PES_packet_length
84            flags
81 18 21 00 51 f4 d7 8e d0   PTS
...
```

### 4.4 音频编码

* 控制通道里协商的是 `audio/mp4a-latm`
* 载荷为 LATM/LOAS 编码（实测存在 LOAS 同步候选）
* **载荷是明文**（V5 已用分布检验证明：卡方 2.75×10⁶，非密文）

---

## 5. 实现清单（第二轮）

要把 `sample-55s.mp3` 推给音箱，发送端需要：

1. **TCP 监听** + **RTSP 服务端**
   * 处理 `OPTIONS` / `GET_PARAMETER` / `SET_PARAMETER` / `SETUP` / `PLAY` / `TEARDOWN`
   * 按 §2.4 回复能力（`wfd_video_formats: none`，纯音频）
   * 生成并维护 `Session`，响应保活
   * 校验 `authMsg` → 计算 `authMsgAck`（算法**仍未解**，见下）
2. **MPEG-TS 复用器**
   * PAT / PMT / PCR / PES 音频
   * PID 分配与 §4.3 对齐
3. **MP3 → AAC-LATM 转码**
   * `MediaCodec` AAC encoder（`audio/mp4a-latm`）
   * 若音箱不接受 ADTS，需要自行封装 LOAS/LATM
4. **RTSP 交织发送**
   * 把 TS 片段切成交织帧，在同一 TCP 连接上写 `'$' | ch | len | payload`

### 未解项：`authMsgAck`

`authMsg`（16 字节）→ `authMsgAck`（32 字节 = HMAC-SHA256 长度）的算法**尚未确定**。
已试并排除：

* `HMAC-SHA256/SHA1(authMsg, key ∈ {authKey, streamKey, streamIV})`
* 反转（key 与 data 对调）
* `SHA256(authMsg || key)` 等拼接形式

说明它还可能牵涉 `Session`、设备 ID 或其他材料。这一项若不解决，
音箱可能拒绝会话 —— **是第二轮最大的未知风险**。

---

## 6. 与既有报告的关系

| 报告 | 结论 |
| --- | --- |
| V2 §3.5 | ❌ `'$' \| length:u16be` 读法不准确 → 本文件 §4.1 修正为 RTSP 交织帧 |
| V2 §4 | ✅ 「音箱拨号平板」方向正确，本文件补充了完整 RTSP 对话 |
| V4 §3.3 | ✅ `wfd://10.42.0.42:38889?mirrorMode=1` 的来源与此处 `wfd_presentation_URL` 一致 |
| V5 | ✅ 音频载荷为明文，故第 2/3 步之后无需解密 |

---

## 7. ★ 完整协商对话（实测，从会话第一包开始）

抓包条件：先开双路采集，再断开重连音箱 —— 因此拿到了**从 OPTIONS 开始的完整流程**。

```
音箱 :57386 ──TCP拨号──> 平板 :40319        (RTSP 协商连接)
音箱 :57390 ──TCP拨号──> 平板 :40319        (音频返回连接)
```

### 7.1 逐条请求/响应

| # | 方向 | 消息 | 关键字段 |
| --- | --- | --- | --- |
| 1 | 音箱→平板 | `OPTIONS *` | `authMsg`, `authKeyType:3`, `authAlgorithmTypes:7`, `wfd_timer_server_port:<a>:<b>`, `lib_version: OH2P-…` |
| 2 | 平板→音箱 | `200 OK` | `authKeyType:2`, **`authAlgorithmVal:4`**, `authMsgAck:<64hex>`, `Public: org.wfa.wfd1.0, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER` |
| 3 | 音箱→平板 | `GET_PARAMETER` | 13 个能力名（见 §7.2） |
| 4 | 平板→音箱 | `200 OK` | 13 项能力值（见 §7.2） |
| 5 | 音箱→平板 | `SET_PARAMETER` | `wfd_type_encryp: 4 1 1 0 0` / **`wfd_audio_codecs_v2: 1 1`** / `wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play` / **`wfd_presentation_URL: rtsp://10.42.0.42/wfd1.0/streamid=0 none`** |
| 6 | 平板→音箱 | `200 OK` | `Content-Length: 0` |
| 7 | 音箱→平板 | `SET_PARAMETER` | **`wfd_trigger_method: SETUP`** ← 触发 SETUP |
| 8 | 平板→音箱 | `200 OK` | |
| 9 | 音箱→平板 | **`SETUP rtsp://10.42.0.42/wfd1.0/streamid=0`** | `Transport: RTP/AVP/TCP;interleaved=0-1`<br>**`MultiPort: image_port=0;multi_port=57390`** ← ★ 音频返回端口 |
| 10 | 平板→音箱 | `200 OK` | `Session: 1350490027;timeout=20`<br>`Transport: RTP/AVP/TCP;interleaved=0-1;` |
| 11 | 音箱→平板 | **`PLAY rtsp://10.42.0.42/wfd1.0/streamid=0`** | `Session: 1350490027` |
| 12 | 平板→音箱 | `200 OK` | `Session: 1350490027;timeout=20`<br>**`Range: npt=now-`** |
| 13 | 音箱→平板 | `TIME_OFFSET` | `TimeOffset:57947083175` |
| 14 | 平板→音箱 | `200 OK` | |
| 15 | 音箱→平板 | `VIDEO_LATENCY`（周期） | `latency:848` / `bitrate:341558` / `rtpPacketNum:716` |

（另：平板周期发 `GET_PARAMETER` … `Session: <id>` 作保活。）

### 7.2 双方能力表（原样）

**平板 → 音箱**（`200 OK` 给 `GET_PARAMETER`，`Content-Length: 400`）：

```
wfd_audio_codecs_v2: 63 3 3
wfd_video_formats: none
wfd_video_enctype: none
wfd_video_gamuttype: none
wfd_video_bitrate: none
wfd_current_video_info: none
wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play
miplay_support_image: none
wfd_standby_resume_capability: supported
wfd_content_SP_protection: 4 1 256 2 1 1 0 0
wfd_support_secure_win:enable
device_info: -1 -1 -1 -1 -1 -1 -1
```

**音箱 → 平板**（`GET_PARAMETER` 请求体，`Content-Length: 299`）：

```
wfd_content_SP_protection
wfd_video_formats
wfd_video_enctype
wfd_video_gamuttype
wfd_video_bitrate
wfd_dynamic_video_enable
wfd_current_video_info
wfd_audio_codecs_v2
wfd_client_rtp_ports
wfd_tcp_enable
wfd_tcp_multi_session_enable
wfd_support_secure_win
wfd_standby_resume_capability
```

### 7.3 ★ 实现要点（与之前实现的三处差异）

1. **`authMsgAck` 已解**：`HMAC-SHA256(key=authKey, msg=authMsg)`，两者按 ASCII
   （见 `AUTH_ACK_ANALYSIS_V1.md` 的修正章节）。实测 4/4 命中。
2. **SETUP 响应必须回 `Transport`**（带尾部 `;`）与
   **`Session: <id>;timeout=20`**；PLAY 响应必须回 **`Range: npt=now-`**。
   我此前只回了 `Session`，缺 `Transport`/`Range`。
3. **音频走 `MultiPort` 指定的新反连**（`multi_port=57390`），
   而不是原 RTSP 连接。音箱在 SETUP 里告知该端口，平板应连它（或接受其连接）
   并在其上发交织音频。

# MIPLAY_VERIFIED_FINDINGS_V7.md

MiPlay（小米妙播）逆向工程 —— **已确认结论清单与撤回记录**

> 本文件是**证据质量的权威记录**，用于替代此前各版本中的未经证实主张。
> 分级：**[实测] / [反汇编] / [源码] / [强推断] / [未知] / [已撤回]**
>
> **制定原则**：宁可少一条结论，也不留一条无法复现的结论。

---

## 0. 一句话状态

**已破解**：局域网发现、控制连接结构、`SafetyKeyDeal` 成员映射、
WFD/RTSP 鉴权算法、完整音频承载结构（TS/PES/交织帧）。

**未破解**：**8899 控制通道的实际 AES key 与 IV**、其与具体 session 的
生命周期关联、`SAFETY_AUTH` 在状态机中的确切位置、
第三方 sender 能否完整独立复现小米 sender。

**结论：尚未实现向音箱推送音频。**

---

## 1. ★ 撤回记录（最高优先级阅读）

### 1.1 撤回项：`137/137 KEY OK`

| 项 | 内容 |
| --- | --- |
| **原主张** | 用 `authKey` 解密 8899 控制通道，得到 137/137 + 159/159 帧 padok；真机会话 36/40；错密钥对照 0/5。据此宣称控制通道**已破解** |
| **撤回日期** | 2026-10-02 |
| **状态** | **已撤回，不得作为证据引用** |

**证伪方法 [实测]**：对**同一帧**用不同 key/IV 解密，观察结果是否随 key 变化。

```
key=authKey   iv=streamIV  第3帧 → 1d3f97d4d4883232cbb7bceb8c58bfa0…
key=authKey   iv=authKey   第3帧 → 1d3f97d4d4883232cbb7bceb8c58bfa0…   ← 与上相同
key=streamKey iv=streamIV  第3帧 → 255781405bcef404688626d513810330…   ← 不同
```

**推导**：在真正的 AES-128-CBC 跨帧链式下，第 N 帧的 IV 来自第 N−1 帧的密文，
因此第 N 帧（N≥2）的**明文只依赖 key**，**不依赖所选初始 IV**；
而第 3 帧的实际输出**随 key 变化**。

→ 说明 `mp_full_decrypt.py` / `verify_live.py` 的**帧解析或链式模型不成立**，
其 `padok > 50%` 判据是**假阳性**，`KEY OK` 判定无效。

**已做的处置**：
1. `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md` —— 表格中的成功率已划删除线并标注撤回；
2. `reports/MIPLAY_CHANNEL_STATUS.md` —— 同上，并改写「可离线复现」一行；
3. `reports/MIPLAY_HANDOFF_FOR_REVIEW.md` —— 同上（该文件曾用于对外评审，**必须重新送审**）；
4. `reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md` —— 顶部加更正说明，「矛盾叙事」整段作废；
5. `captures/tools/mp_full_decrypt.py`、`captures/tools/verify_live.py` ——
   头部加 `RETRACTED ORACLE` 横幅，并把 `KEY OK` 判定替换为
   `ORACLE-UNSOUND`，防止再次误用。

### 1.2 连带作废的推论

| 原推论 | 状态 |
| --- | --- |
| 「8899 控制通道已破解」 | ❌ 作废 |
| 「存在 137/137 成功、新会话 0/9 的矛盾」 | ❌ **前提不存在**；真实情况是 key 从未找到 |
| 「可能因此存在第四把 cmdKey」 | ⚠️ 该推测的**依据**已消失，退回为 [未知] |

> **教训**：`padok`（零填充自校验）**不是可靠的密钥判据**。
> 它依赖对帧结构与链式方式的假设；假设错了，判据就失效。
> 可靠做法是 §5 的**动态取 key**。

### 1.3 单个帧的 CRC 字段是真实的（与上面不同，这一条成立）

**[实测]** 帧体 `00 07 01 e0 | flags:u8 | pad:u8 | crc32be:4 | ct` 中的 CRC
**确为** ciphertext 的字节反转 CRC-32，8/8 帧全部匹配：

```
cmd=0x06 crc=0x55f3510f calcBE=0x55f3510f  CRC-OK
cmd=0x12 crc=0x447cf904 calcBE=0x447cf904  CRC-OK
...
```

→ **帧结构解析是正确的**；出错的是**链式/密钥模型**。

---

## 2. 已确认结论（可复现）

### 2.1 局域网发现 [实测]

* 只有**音箱**在 mDNS 广播（`_mi-connect._udp` / `_lyra-mdns._udp`）；
  **发送端不广播**。
* → 发送端不是靠 mDNS 被发现的；音箱是从 **8899 控制通道**获知「往哪儿拨」
  （`SET_MIRROR_KEY` 内的 `wlan0ip` + `wfd://<IP>:<端口>`）。

### 2.2 WFD/RTSP 鉴权算法 ★ 硬证据 [实测]

```
authMsgAck = HMAC-SHA256(key = authKey, msg = authMsg)      # 两者均按 ASCII
```

* **7/7 真实向量命中**，跨 3 个会话（含**平板重启后**的会话）；
* 回归脚本：`MiPlayDiscovery/tools/verify_auth_vectors.py`
* `authKey = uuid[:16]`，由 `ProtocolSession.getKey()` 生成；
* 关键实现细节：**标准 HMAC**（opad `0x5c`）。
  > 更正：早先一版曾声称 opad 为 `0x6a`（非标准），**该说法错误**，
  > 已由「标准 `hmac.new()` 一次命中 4/4」直接证伪。

### 2.3 `SafetyKeyDeal` 成员映射 ★ 三条独立汇编证据 [反汇编]

| 证据 | 位置 | 内容 |
| --- | --- | --- |
| ① | `SafetyKeyDeal` ctor `0x2566cc` | string → `+0x00/+0x20/+0x40`；uint16 → `+0x18/+0x38`；`+0x58/+0x70/+0x88` 置空 |
| ② | `CmdSource::onSessionConnect` `0x175ef0` | `basic_string::operator=`：`+0x58←0x360`、`+0x70←0x378`、`+0x88←0x390` |
| ③ | `CmdSource::setLyraInfo` `0x16d578` | 每个赋值**紧邻**的 JSON 字面量：`authKey→0x360`、`streamKe→0x378`、`streamIV→0x390` |

```
JSON "authKey"   → CmdSource+0x360 → SafetyKeyDeal+0x58
JSON "streamKey" → CmdSource+0x378 → SafetyKeyDeal+0x70
JSON "streamIV"  → CmdSource+0x390 → SafetyKeyDeal+0x88
genAesKey(type=4) → 读 +0x58 ；genAesIv(type=4) → 读 +0x88 ；genAuthKey(type=2) → 读 +0x58
```

**注意**：这只是**静态映射**。它**不等于**「设备上 8899 实际用的就是 authKey/streamIV」——
后者**至今未被观测验证**（§4）。

### 2.4 `safetyIntegrityData` 与鉴权无关 [反汇编]

`_Z19safetyIntegrityDatajjPKhm` @`0x2576e4`，共 20 条指令：

```asm
cmp  w0, #1
b.ne ret_m1            ; type != 1 → return -1
mov  w0, wzr
bl   av_crc_get_table  ; FFmpeg
b    av_crc            ; FFmpeg CRC-32
```

→ 只是 `av_crc` 包装，**不是认证**。

### 2.5 完整 WFD/RTSP 协商对话 [实测]

从会话第一包开始完整捕获（先 arm 双路采集，再断开重连音箱）：

```
音箱 → 平板  OPTIONS *            authMsg/authKeyType:3/authAlgorithmTypes:7
平板 → 音箱  200 OK              authKeyType:2 / authAlgorithmVal:4 / authMsgAck:<64hex>
音箱 → 平板  GET_PARAMETER       (13 项能力名)
平板 → 音箱  200 OK              wfd_audio_codecs_v2: 63 3 3 / wfd_video_formats: none …
音箱 → 平板  SET_PARAMETER       wfd_audio_codecs_v2: 1 1 / wfd_type_encryp: 4 1 1 0 0
音箱 → 平板  SET_PARAMETER       wfd_trigger_method: SETUP
音箱 → 平板  SETUP               Transport: RTP/AVP/TCP;interleaved=0-1
                                 MultiPort: image_port=0;multi_port=<port>   ← 音频返回端口
平板 → 音箱  200 OK              Session: <id>;timeout=20 / Transport: …;
音箱 → 平板  PLAY                Session: <id>
平板 → 音箱  200 OK              Session: <id>;timeout=20 / Range: npt=now-
音箱 → 平板  TIME_OFFSET / VIDEO_LATENCY（周期）
```

### 2.6 音频承载结构 [实测]

```
RTSP 交织帧 : '$' | channel:u8 | length:u16be | payload
              解析 3,095,052 字节 → 3502 帧、100.00% 消费、0 次重同步、channel 恒为 0
payload     : 12 字节私有头 + MPEG-TS
              `80 a1 | seq:u16be | 0000 | deadbeef | subtype:u16be`  (TS 起点 = payload+12)
MPEG-TS     : PAT 0x0000 / PMT 0x0100 / PCR 0x1000 / 音频 PES 0x1100 (stream_id 0xC0, 带 PTS)
编码声明     : audio/mp4a-latm
```

> 注：音频**基本流**（PES 内部）的确切封装形态（ADTS / LOAS / 其他）
> **离线未能判定** —— 提取出的 ES 熵 7.82、卡方 1.2×10⁶，既不符合 ADTS
> 也不符合 LOAS 的同步统计。[未知]

### 2.7 已交付代码与测试 [实测]

| 组件 | 状态 |
| --- | --- |
| `MiPlayWire.kt`（帧格式 + CRC32） | ✅ 13 项测试 |
| `MiPlayCrypto.kt`（AES-128-CBC 链式） | ✅ 含在 13 项内 |
| `media/TsMuxer.kt`（PAT/PMT/PCR/PES） | ✅ 10 项测试 |
| `media/WfdRtspServer.kt`（含已解出的 `authMsgAck`） | ✅ 6 项测试（4 条真实向量） |
| `media/AacLatmEncoder.kt` / `AudioPushSession.kt` | ✅ 编译通过（**未上机**） |
| **合计** | **38/38 通过** |

> ⚠️ `MiPlayCrypto.kt` 的 AES 实现**基于未经验证的 §2.3 静态映射**，
> 在 §4 被观测证实之前，**不应视为可用**。

---

## 3. 时间线：102 秒的关键事实 [实测]

```
16:07:40   8899 控制会话建立（首个 SYN 包）
   │
   ├── 加密流量持续（52 + 62 帧，ct 长度 16/32/48/96/128/160/176）
   │
   │        ← 这段时间内的 key/IV 从未被观测到
   │
16:09:22   logcat 出现唯一一次密钥生成
           uuid:961d3dbbd77041a89de4b570959352aa  → authKey   961d3dbbd77041a8
           uuid:90a2664c89ed403ea5d3e06a88a73659  → streamKey 90a2664c89ed403e
           uuid:bd10fac0fefd4be4bd7ba6d0800617db  → streamIV bd10fac0fefd4be4
```

**这 102 秒的间隔本身就是最重要的证据**：
会话建立时所用的密钥**早于**我们唯一观测到的密钥生成事件，
说明**此前拿到并用于解密的 key，很可能从未与目标 session 建立关联**。

**[实测]** 本轮用该会话的全部 3 把 key（ASCII + hex 两种形态 = 6 种）
× 全部 3 把候选 IV × 两种链式模式，对 52+62 帧解密：**0 命中**。

---

## 4. 未破解项（明确列出，避免再次误判）

| # | 未破解 | 状态 |
| --- | --- | --- |
| U1 | **8899 实际 AES key** | [未知] |
| U2 | **8899 实际 IV** | [未知] |
| U3 | key 与**具体** 8899 session 的生命周期关联 | [未知] |
| U4 | `SAFETY_AUTH` 在状态机中的确切位置与载荷 | [未知] |
| U5 | 第三方 sender 能否完整独立复现小米 sender | [未知] |
| U6 | 音频 ES 的确切编码封装 | [未知] |
| U7 | PES 载荷中出现的 `50 4B 03 04`（ZIP 局部文件头） | [TODO · 暂不追] |

**动态取 key 的路被堵死 [实测]**：
```
/proc/<pid>/mem            → Permission denied
run-as com.milink.service  → package not debuggable
getenforce                 → Enforcing
```
无 root，静态分析已到边界。

---

## 5. 下一阶段路线（已定）

**不再进行任何盲解密尝试。**

目标是：

> **证明某个具体 8899 session 在某个具体时间点使用了哪一个 AES context。**

### 5.1 观测点

Hook **`AES_init_ctx_iv(ctx, key, iv)`**（或等价的 `mbedtls_aes_setkey_*`），记录：

```
timestamp | thread | native backtrace | ctx | key[16] | iv[16]
```

同时 hook（用于建立关联）：
`CmdSource::setLyraInfo`、`SafetyKeyDeal::genAesKey`、`SafetyKeyDeal::genAesIv`、
`SafetyDataDeal::SafetyDataDeal`。

### 5.2 需要的证据链

```
session A
  ├─ createCmdSession()
  ├─ setLyraInfo()
  ├─ setMirrorKey()      → authKey / streamKey / streamIV
  ├─ SafetyKeyDeal(...)
  ├─ AES_init_ctx_iv(...) → 真实 key / IV        ★ 关键观测
  └─ 第一条加密帧
        ↓
  同一 session 的 PCAP
        ↓
  离线复现 → 得到确切明文
```

### 5.3 前置条件（三选一）

| 方案 | 说明 |
| --- | --- |
| **root 平板** | 最直接，Frida 可注入 |
| **Frida gadget + 重打包 debug 版** | 无需 root，但要改 APK |
| **userdebug/eng ROM** | 最干净，但需刷机 |

### 5.4 若观测结果出乎意料

如果发现 AES 初始化所用的**根本不是** `authKey / streamKey / streamIV`，
那**同样是高价值结果** —— 它会直接指出应追的下一个对象，
而不是继续在协议层猜测。

---

## 6. 本文件的维护约定

1. 任何结论必须能复现；不能复现的**一律撤回**，不标「待确认」。
2. 单次 oracle 命中（如 padok 比例）**不构成破解证据**；
   必须给出「同 key 下 N≥2 帧连续正确」或**动态取 key**。
3. 撤回项保留在 §1，**不删除**，以保证审计链完整。

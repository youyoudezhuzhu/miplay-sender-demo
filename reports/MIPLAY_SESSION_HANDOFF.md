# MiPlay 项目交接文档（SESSION HANDOFF）

> 面向**新会话**的完整交接。读完本文应能直接继续，无需回看历史对话。
> 仓库：https://github.com/youyoudezhuzhu/miplay-sender-demo （HEAD `cd7b0da`）

---

## 0. 一句话现状

**控制通道密码已完全破解并经交叉验证；协议栈已还原；NAS 端第三方 sender 已实现但被音箱卡在 `0x29` AUTH_20 之后断开。音频推流尚未跑通。**

**当前唯一目标**：让 NAS（或任意第三方）作为 sender，把音频推到小爱音箱。

---

## 1. 环境（当前实测可用）

| 项 | 值 |
| --- | --- |
| NAS 热点 | `MiPlayLab`，`wlo1` = **10.42.0.1/24**，activated |
| 平板 | `10.42.0.42`（Redmi Pad 6，`xun`，Android 15，`OS2.0.209.0.VMUCNXM`） |
| 音箱 | `10.42.0.127`（Xiaomi Soundbox OH2P，MAC `90:fb:5d:d3:43:1e`） |
| adb（USB） | 序列号 **`429917f0`**，USB 直连 |
| **root** | ✅ `su -c id` → `uid=0(root) context=u:r:ksu:s0`（KernelSU） |
| SELinux | `Permissive`（由 `fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive` + `fastboot continue` 设置） |
| frida-server | ✅ 以 **root** 运行（`/data/local/tmp/frida-server`，PID 11718） |
| Frida 工具 | `/opt/frida/venv/bin/frida`（venv，frida 17.20.0） |
| 目标进程 | `com.milink.service:audio`，**PID 5659**，持有 8899 socket（**fd 207**） |
| 工具链 | fastboot/adb `/opt/android-sdk/platform-tools`；ffmpeg `/bin/ffmpeg` |

**root 获取方式（可复现）**：
```bash
adb reboot bootloader
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
fastboot continue
# 开机后在 KernelSU 里给 ADB shell 授权 root
```

---

## 2. ✅ 已确认结论（可复现，可依赖）

### 2.1 8899 控制通道密码 ★ 核心成果

```
AES-128-CBC，零填充（pad = 16 - (len % 16)，恒 1..16）
    key       = authKey        （uuid[:16]，ASCII，不 hex 解码）
    IV(首帧)  = authKey        ← 不是 streamIV
    IV(后续)  = 上一帧密文最后 16 字节（自由链式，每个方向各自维护）
```

**帧结构**（逐字节核对过）：
```
'$'(0x24) | outer:u8 | cmd:u8 | seq:u16be | bodyLen:u32be | body
加密 body = 00 07 01 e0 | pad:u8 | crc32be:4 | ciphertext      ← 头 9 字节，ct 从 offset 9 开始
CRC       = CRC-32/MPEG-2（poly 0x04C11DB7，非反射，init 0xFFFFFFFF），4 字节倒序存放
            ⚠️ 不是 zlib.crc32（那是反射变体，不匹配）
```

**交叉验证（决定性证据）**：从 8899 加密通道解出的 `authMsgAck`
恰好等于反方向 `authMsg` 的 HMAC —— **一把 key、两条独立协议互证**。

- 报告：`reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md`
- 回归脚本：`MiPlayDiscovery/tools/verify_cmd_channel.py`（ALL CHECKS PASSED）
- 工具：`MiPlayDiscovery/tools/solve_cmd_key.py`、`captures/tools/decode_8899.py`

### 2.2 WFD/RTSP 鉴权

```
authMsgAck = HMAC-SHA256(key = authKey, msg = authMsg)    ← 标准 HMAC（opad 0x5c）
两者均按 ASCII；输出 64 字符小写 hex
```
**7/7 真实向量命中**（跨 3 个会话，含重启后）。
回归：`MiPlayDiscovery/tools/verify_auth_vectors.py`

### 2.3 官方握手明文顺序（从网上直接观测）

```
<- 0x28 DEVICE_ID（seq 高值，如 1471）
-> 0x36 GET_VERSION (seq 0)
<- 0x37 版本 "2.2.4112519"
-> 0x29 AUTH_20（**等待 0x37 之后发**；mirror 对端 seq；body = 20 随机字节的 40 位 hex）
-> 0x00 能力声明（**明文**，129 字节 frame，tab 缩进 + 尾部空格）
<- 0x01 协商应答（**明文**）{"aesIvType":"4","aesKeyType":"4","authAlgorithmType":"4",
                          "authKeyType":"2","integrityType":"1","result":"0"}
<- 0x02 加密挑战（内含 authMsg）
-> 0x03 加密应答（authMsgAck）
... 之后 0x6c setMirrorKey + 0x00 wfd://<ip>:<port>?mirrorMode=1
```

**`0x29` 帧与官方逐字节结构一致**（本轮已排除）：
```
官方: 240029 05bf 00000028 b17e5e1dbd20c32d9b66ec4e8726d3d528480116
NAS : 240029 0000 00000028 <20随机字节的40位hex>
```
→ **帧本身没问题**，差异在**连接状态或前置准备**。

### 2.4 音频承载结构

```
RTSP 交织帧: '$' | channel:u8 | length:u16be | payload（3502 帧/100% 消费/0 重同步/channel 恒 0）
payload    : 12 字节私有头 + MPEG-TS
             80 a1 | seq:u16 | 0000 | deadbeef | subtype:u16   (TS 起点 = payload+12)
MPEG-TS    : PAT 0x0000 / PMT 0x0100 / PCR 0x1000 / 音频 PES 0x1100 (stream_id 0xC0, 带 PTS)
编码声明    : audio/mp4a-latm
```
音频通道**本身是明文**（统计检验证明，见 `reports/MIPLAY_CRYPTO_ANALYSIS_V5.md`）。

音箱**反向拨号**到 sender：`SETUP` 里 `MultiPort: multi_port=<port>` 告知音频回传端口。

### 2.5 其它已确认

- **mDNS 只有音箱在广播**，sender 不广播 → 音箱是从 8899 的 `setMirrorKey` 学到往哪儿拨
- `safetyIntegrityData` = `av_crc` 包装（20 条指令），**与鉴权无关**
- `SafetyKeyDeal` 成员映射（三条独立汇编证据）：`+0x58`←authKey、`+0x70`←streamKey、`+0x88`←streamIV
- 密钥是系统服务**每会话随机生成**（`uuid[:16]`），非身份派生、非账号绑定

---

## 3. ❌ 未解决 / 当前卡点

### 3.1 主卡点：NAS sender 在 `0x29` 后被音箱断开

实测（平板离线、只有 NAS 在说话）：
```
✅ TCP connect 接受
✅ <- 0x28 DEVICE_ID + 0x1b 心跳（每 5s，连接能活 26s）
✅ <- 0x37 回应我们的 0x36
❌ -> 0x29 AUTH_20  → 音箱立即关闭
❌ 从未收到 0x01 ack / 0x02 challenge
```

**已排除**：
- 帧结构/长度（与官方逐字节一致）
- 随机性（已改随机 20 字节）
- seq（已 mirror 对端）
- 节奏（试过背靠背 / 间隔 0.4s / 等 0x37 再发）
- 能力声明内容（与官方逐字节一致）
- 平板占用（已确认平板离线）

**未排除**：连接状态、前置准备（如 `EncryKey::GetStringAesKey` 是否需要先调用）

### 3.2 Hook 覆盖不足（技术障碍）

hook libc `send`/`sendto`/`write`/`writev`/`sendmsg` + 过滤 `0x24` 开头帧
→ **只看到 fd=239（音频）**，8899 控制帧（fd 207）**从不出现**。

→ **控制通道不走这些 libc 入口**，走库自己的封装。

### 3.3 其它未知

- 音频 ES 的确切编码封装（ADTS / LOAS / 其它）—— 离线未能判定
- PES 载荷中出现的 `50 4B 03 04`（ZIP 局部文件头）—— 留 TODO，暂不追

---

## 4. ▶️ 下一步（明确、成本排序）

### 第 1 优先：hook 库的 socket 写路径

符号已确认存在于 `libaudiomirror-jni.so`：
```
mirror::net::TCPSession::writeMoreEb
mirror::net::Session::writeDirectEPKcl
mirror::net::TCPSession::wantsToWriteEv
mirror::net::MPTSession::writeMoreEb
```
**目标**：拿到官方 `0x29` 的**发送现场**，看它前后有没有别的调用（尤其是 key 初始化）。

### 第 2 优先：hook `EncryKey::GetStringAesKey`

符号：`_ZN6mirror8EncryKey15GetStringAesKeyEPKhi`
**验证假设**：官方在 `0x29` 之前是否做了一次本地 crypto/key 初始化，而 NAS 没做。

### 第 3：`AES_CBC_encrypt_buffer` 与具体帧的时间对齐

已确认它会触发，context 里可读到 IV（例：`dc34ee6d489c1175e400d9097caf7317`），
但**尚未把某次调用与某个控制帧对应**。

### 现成脚本

| 文件 | 作用 |
| --- | --- |
| `/tmp/mp/hook_ctl.js` | hook AES enc/dec + fd=207 的 send |
| `/tmp/mp/hook_ctl2.js` | hook 全部 write 变体，过滤 `0x24` 帧 |
| `/tmp/mp/hook_enc.js` | hook `SafetyDataDeal::encryptData`（**实测不触发**，保留参考） |
| `/tmp/mp/hook_all.js` | hook send + AES + key 函数 |

启动方式：
```bash
/opt/frida/venv/bin/frida -U -p 5659 -l /tmp/mp/hook_ctl2.js -q
```

---

## 5. ⚠️ 踩过的坑 / 避免重犯

### 5.1 我犯过并已撤回的错误（**不要重复**）

| 错误结论 | 真相 |
| --- | --- |
| 「137/137 padok → 8899 已破解」 | **假阳性**。padok 判据不成立（判据已从工具中移除） |
| 「OAuth::hmac opad 是 0x6a」 | 错。是**标准** HMAC（0x5c） |
| 「音箱拒绝我们（能力声明后断开）」 | 错。当时是 `parse_frames` 不消费缓冲区的 bug |
| 「音箱没有拒绝我们」 | **又错**。我引用的"成功 ack"来自**平板**的流量（`spk.pcap` 源地址是 10.42.0.42，NAS 根本没出现）。**核对证据来源的源地址** |

### 5.2 技术陷阱

- **`cryptography` 的 `CipherContext.update()` 会自己加 PKCS#7 填充** → 会在设备的零填充之上多一个块。必须只喂 block-aligned 数据
- **CRC 是 MPEG-2 变体**，不是 zlib
- **pad 字节 == 明文尾部零字节数**（逐帧验证：0x02→2, 0x0f→15, 0x10→16, 0x0a→10, 0x08→8）
- **不要把 `0x24` 当帧内重同步标记**
- **密钥必须与会话同窗口采集**：曾出现会话建于 16:07:40、密钥生成于 16:09:22（**晚 102 秒**）→ 必然解不开
- `pkill -f <pattern>` 会杀掉自己的 shell（本会话踩过 3 次）→ 用精确 PID 或 `fuser`
- Frida 里 `hexdump` 是内建名，**不能自定义同名函数**

### 5.3 设备/网络

- 平板保持 Wi-Fi 连热点；**平板连着音箱时会干扰 NAS 测试**（音箱可能同时只服务一个 sender）
- 音箱**重连过快会被限流**（曾出现连接即断），需要退避
- 平板没连热点时 `ip -o -4 addr show` 只有 `lo`

---

## 6. 仓库结构 / 交付物

| 路径 | 内容 |
| --- | --- |
| `reports/MIPLAY_VERIFIED_FINDINGS_V7.md` | **权威结论清单 + 撤回记录**（先读这个） |
| `reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md` | 8899 破解最终结果 + 交叉验证 + 复用代码 |
| `reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md` | 完整 WFD/RTSP 对话 + 音频承载结构 |
| `reports/MIPLAY_CRYPTO_ANALYSIS_V5.md` | 音频明文证明 |
| `MiPlayDiscovery/tools/nas_sender/` | **NAS sender**（wire/tsmux/rtsp/sender + 17 测试 + README） |
| `MiPlayDiscovery/tools/verify_cmd_channel.py` | 8899 密码回归（含负向断言） |
| `MiPlayDiscovery/tools/verify_auth_vectors.py` | authMsgAck 7/7 回归 |
| `MiPlayDiscovery/tools/miplay_aes_trace.js` | Frida 插桩脚本（AES + key 路径） |
| `MiPlayDiscovery/` (APK) | 平板端 demo（发现 + 多选 + 控制通道；音频推流组件已写未上机） |

**测试状态**：`nas_sender` **17/17 通过**；`miplay-sender` Kotlin **38/38 通过**。

```bash
cd MiPlayDiscovery/tools/nas_sender
python3 -m tests.test_wire    # 9 passed
python3 -m tests.test_tsmux   # 8 passed
```

---

## 7. 建议的新会话开场

> 项目在 `/vol1/@appdata/deepseek.harness/home/github`，已发布到
> `github.com/youyoudezhuzhu/miplay-sender-demo`（HEAD `cd7b0da`）。
>
> 先读 `reports/MIPLAY_VERIFIED_FINDINGS_V7.md` 和
> `MiPlayDiscovery/tools/nas_sender/README.md`。
>
> **现状**：8899 控制通道密码已破解并交叉验证；NAS 端第三方 sender 已实现，
> 但音箱在我们发 `0x29` AUTH_20 后立即断开。`0x29` 帧与官方逐字节结构一致，
> 已排除帧本身的问题。
>
> **环境**：adb `429917f0`（USB）、已 root（KernelSU）、SELinux Permissive、
> frida-server 以 root 运行、目标进程 `com.milink.service:audio` PID **5659**、
> 8899 socket 是 **fd 207**。热点 10.42.0.1，平板 10.42.0.42，音箱 10.42.0.127。
>
> **下一步**：hook `mirror::net::TCPSession::writeMore`（libc 的 send/write
> hook 不到控制通道），拿到官方 `0x29` 的发送现场；并 hook
> `EncryKey::GetStringAesKey` 验证官方是否在 `0x29` 前做了 key 初始化。
>
> **禁止**：不要再猜 HMAC/KDF；不要再盲试密钥；引用任何"成功"证据前
> **先核对源地址**（我曾把平板流量误当自己的成功）。

# MiPlay 妙播 — 发送端逆向与 Android Demo

小米妙播（MiPlay / Mi Connect）**发送端协议**的逆向分析与可运行 Android Demo：
**发现局域网内的小爱音箱 → 多选 → 建立加密控制通道**。

> ⚠️ 本项目为**互操作性研究 + 个人自用**。与小米官方无关联，不含任何小米专有二进制。
> 详见文末「合法性」。

---

## 结果速览

| 通道 | 加密 | 状态 |
| --- | --- | --- |
| **控制通道 TCP 8899** | AES-128-CBC | ✅ **已完全解密** |
| 音频通道（MPEG-TS / PES） | **无加密** | ✅ 实测证实为明文 |
| RTSP / WFD | 无加密 | ✅ 明文可读 |

关键结论（部分与直觉相反，但都有实测依据）：

1. **控制通道的 AES key 是 `authKey`，不是 `streamKey`** —— `genAesKey(type=4)`
   读 `SafetyKeyDeal+0x58`，而该成员由 `onSessionConnect` 从 `authKey` 字段填充。
2. **IV = `streamIV`，且跨帧自由链式**（`IV := 上一段密文最后 16 字节`）。
3. **零填充**，`pad = 16 - (len % 16)`，恒为 1..16。
4. **密钥无法从抓包推导** —— 发送端用 `UUID.randomUUID()` 前 16 个字符，
   但官方会在 logcat **明文打印**它。
5. **音频通道根本没有加密** —— 分布检验证明：原始载荷卡方 2.75×10⁶（高度结构化），
   而任何 AES 解出来都是卡方 ≈224 的均匀噪声（`解密把结构抹掉了`）。

完整论证见 [`reports/`](reports/)。

---

## Demo 能力（v0.2.0）

### ✅ 已实现，且有单元测试

| 能力 | 说明 |
| --- | --- |
| mDNS 发现 | `_mi-connect._udp` / `_lyra-mdns._udp`，解析 TXT / SRV / appsData |
| 多选 UI | 设备卡片复选框 + 全选，实时显示已选数量 |
| 控制通道握手 | TCP 8899：`GET_VERSION` → `AUTH_20` → 能力协商 |
| AES-128-CBC | key=`authKey`，IV=`streamIV`，跨帧链式，零填充，CRC32 校验 |
| `SET_MIRROR_KEY` | 按官方字段顺序加密下发媒体密钥 |
| 原始协议日志 | 逐帧 RX/TX，可对照抓包 |

**13 个单元测试全部通过**，且**直接钉在真实抓包数据上**——格式或算法一旦漂移，测试立刻失败。

### ❌ 尚未实现：音频推流

把 `sample-55s.mp3` 播到音箱这一步**尚未实现**。困难不在密码学（音频本来就明文），
而在于发送端要自己充当 **WFD RTSP 服务器**，等音箱**反向拨入**后，
把 `MP3 → AAC-LATM → MPEG-TS` 推过去。需要：

1. `org.wfa.wfd1.0` RTSP 服务端（OPTIONS / GET_PARAMETER / SET_PARAMETER / SETUP / PLAY）
2. MPEG-TS 封装（PAT / PMT / PCR / PES）
3. MP3 → AAC-LATM 转码（MediaCodec）
4. 处理反向连接与 WFD 分片

`sample-55s.mp3` 已打进 APK 的 `assets/`，作为下一轮素材。

---

## 快速开始

```bash
cd MiPlayDiscovery

# 单元测试（13/13 通过）
./gradlew :miplay-sender:testDebugUnitTest

# 构建 Demo APK
./gradlew :miplay-discovery-test:assembleDebug
# -> miplay-discovery-test/build/outputs/apk/debug/miplay-discovery-test-debug.apk
```

安装后：确保手机与音箱**同一局域网** → 「开始扫描」→ 勾选音箱 → 「连接所选音箱」→ 看日志。

Android 13+ 首次运行如提示**本地网络权限**请允许；mDNS 依赖
`CHANGE_WIFI_MULTICAST_STATE`（manifest 已声明）。

详见 [`MiPlayDiscovery/DEMO_README.md`](MiPlayDiscovery/DEMO_README.md)。

---

## 真机验证（2026-10-02）

对真实小爱音箱 `MiAiSoundbox-OH2P`（`10.42.0.127`）实测：

* **明文握手**：直连音箱，`0x28 DEVICE_ID` → `0x36 GET_VERSION` → `0x37 "2.2.4112519"`，
  命令码与「音箱先说话」的顺序全部吻合；
* **控制通道解密**：用平板 logcat 里的当次会话密钥，对**正在运行**的 8899 会话解密：

```
# control key (authKey) = b'f79ebd58d44d4348'
# control IV  (streamIV)= b'53af259081674f56'
dir 55546: padok 18/20
dir 8899 : padok 18/20
TOTAL 36/40  -> KEY OK
```

复现：`python3 MiPlayDiscovery/tools/verify_live.py <logcat.txt> <capture.pcap>`

> 注：**音频推流仍未实现**（见上）。从外部主机也无法发起推流，因为协议方向是
> **音箱拨号到发送端**，发送端必须自己当 RTSP/WFD 服务器。

---

## 仓库结构

```
MiPlayDiscovery/
├── miplay-discovery/       # mDNS 发现引擎（可复用 AAR）
├── miplay-sender/          # 控制通道 + 会话加密（含 13 个单测）
│   └── src/main/java/com/fusionplay/miplay/sender/
│       ├── MiPlayWire.kt           # 帧格式 + CRC32 + envelope
│       ├── MiPlayCrypto.kt         # 会话密钥 + AES-128-CBC 链式编解码
│       └── MiPlayControlClient.kt  # TCP 8899 客户端 + 握手
└── miplay-discovery-test/  # Demo App
├── tools/                  # 真机验证脚本（verify_live.py / miplay_keys.py）
reports/                    # 逆向分析报告
.github/workflows/          # CI + Release
```

---

## CI / Release

* `.github/workflows/miplay-android-ci.yml` —— push/PR 自动跑单测 + 产出 APK
* `.github/workflows/miplay-release.yml` —— 打 `v*` tag 自动发布 APK

Release 签名：若配置 `RELEASE_KEYSTORE_BASE64` 等 secrets 则用自定义 keystore，
否则回退 debug keystore（可侧载，不适合上架）。

---

## 合法性

* 本项目用于**互操作性研究与个人自用**，逆向自作者本人拥有的设备。
* **不包含也不分发**小米的任何专有二进制（未内嵌 MiLink APK / SDK / `.so`）。
* `sample-55s.mp3` 为测试音频素材；如涉版权请自行替换。
* 与小米官方无任何关联。使用者需自行遵守当地法律及设备服务条款。

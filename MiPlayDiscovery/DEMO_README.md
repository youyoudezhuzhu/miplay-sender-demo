# MiPlay 妙播 发送端 Demo

Android 发送端 demo：**发现局域网内的小爱音箱 / 小米设备 → 多选 → 建立加密控制通道**。

本工程建立在两轮逆向分析的结论之上：

| 报告 | 内容 |
| --- | --- |
| `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md` | TCP 8899 控制通道 **已完全解密** |
| `reports/MIPLAY_CRYPTO_ANALYSIS_V5.md` | 音频通道 **证实为明文** MPEG-TS |

---

## 1. 本版本实现了什么（v0.2.0）

### ✅ 已实现并有单元测试覆盖

| 能力 | 说明 |
| --- | --- |
| **mDNS 发现** | `_mi-connect._udp` / `_lyra-mdns._udp`，解析 TXT / SRV / appsData，聚合出设备名、IP、型号、deviceId |
| **多选** | 设备卡片带复选框，支持「全选 / 全不选」，实时显示已选数量 |
| **控制通道握手** | TCP 8899：`GET_VERSION` → `AUTH_20` → 能力协商（`aesKeyType` 等） |
| **AES-128-CBC 编解码** | key = `authKey`，IV = `streamIV`，**跨帧自由链式**，零填充；含 CRC32 完整性校验 |
| **SET_MIRROR_KEY** | 可按官方字段顺序构造并加密下发 `{"wlan0ip","authKey","streamKey","streamIV"}` |
| **原始协议日志** | 逐帧记录 RX/TX，便于对照抓包 |

**13 个单元测试全部通过**，且直接**钉在真实抓包数据上**（例如
`00 07 01 e0 10 5636e096 | <16B ct>` 这条真实 HeartBeat 帧的 CRC 校验），
所以格式或算法一旦漂移，测试立刻失败。

```
./gradlew :miplay-sender:testDebugUnitTest     # 13/13 pass
./gradlew :miplay-discovery-test:assembleDebug # 产出 APK
```

### ⚠️ 关键：控制通道的密钥从哪来

控制通道在 `SAFETY_AUTH` 之后**就是密文**。解密需要本次会话的
`authKey` / `streamIV`，而它们是**发送端本地随机生成**的
（`UUID.randomUUID()` 前 16 个字符），**不在网络上传输**，
因此**无法从抓包推导**。

官方发送端会把它们打印在 logcat（未脱敏）：

```
I/Cir_Miplay_ProtocolSession: generatorMirrorKey:
I/Cir_Miplay_UUIDGenerator: uuid:<32 hex>   <- authKey
I/Cir_Miplay_UUIDGenerator: uuid:<32 hex>   <- streamKey
I/Cir_Miplay_UUIDGenerator: uuid:<32 hex>   <- streamIV
```

拿到后调用 `MiPlayControlClient.installSessionKeys(...)` 即可武装解密器。
本 demo 已预留该入口，并会把解出的明文帧直接显示在日志里。

---

## 2. 本版本**没有**实现什么（诚实说明）

### ❌ 音频推流尚未实现

用户希望「选择音箱后输出 `sample-55s.mp3`」，这一步**本版本未完成**。
原因不是加密（音频本来就是明文），而是**发送端的媒体链路需要重新实现一整套**：

```
平板必须自己当 RTSP/WFD 服务器
        ▲
        │  音箱反向拨入（注意方向！）
        │
    wfd://<平板IP>:<port>?mirrorMode=1
        │
        ▼
平板把 MP3 → AAC-LATM → MPEG-TS → 经该 TCP 连接推给音箱
```

需要实现：

1. `org.wfa.wfd1.0` 的 **RTSP 服务端**（OPTIONS / GET_PARAMETER / SET_PARAMETER / SETUP / PLAY）
2. **MPEG-TS 封装**（PID 0x0000 PAT、0x0100 PMT、0x1000 PCR、**0x1100 PES 音频**）
3. **MP3 → AAC-LATM** 转码（MediaCodec），并按 WFD 要求的分片方式组包
4. 处理音箱**反向连接**（不是平板主动连音箱）

`sample-55s.mp3` 已经打进 APK 的 `assets/`，作为下一轮的输入素材。

> 顺带说明：V5 已证明音频 TS 载荷是**明文**，所以第 3、4 步一旦做出来，
> 不需要任何额外解密。

---

## 3. 目录结构

```
MiPlayDiscovery/
├── miplay-discovery/          # mDNS 发现引擎（可复用 AAR）
│   └── src/main/java/com/fusionplay/miplay/discovery/
├── miplay-sender/             # ★ 本轮新增：控制通道 + 会话加密
│   └── src/
│       ├── main/java/com/fusionplay/miplay/sender/
│       │   ├── MiPlayWire.kt          # 帧格式 + CRC32 + envelope
│       │   ├── MiPlayCrypto.kt        # 会话密钥 + AES-128-CBC 链式编解码
│       │   └── MiPlayControlClient.kt # TCP 8899 客户端 + 握手
│       └── test/java/.../MiPlayWireTest.kt   # 13 个测试，钉在真实抓包上
└── miplay-discovery-test/     # Demo App（发现 + 多选 + 控制面板）
    └── src/main/assets/sample-55s.mp3     # 音频素材（供下一轮使用）
```

---

## 4. 使用

1. 安装 APK，确保手机/平板与音箱在**同一局域网**
2. 点「开始扫描」→ 等待小爱音箱出现（mDNS 需要几秒）
3. 勾选一台或多台音箱
4. 点「连接所选音箱」→ 观察日志里的握手过程与收到的帧

> Android 13+ 首次运行时如提示本地网络权限，请允许；
> mDNS 依赖 `CHANGE_WIFI_MULTICAST_STATE`（manifest 已声明）。

---

## 5. 构建

```bash
cd MiPlayDiscovery
./gradlew :miplay-sender:testDebugUnitTest       # 单测
./gradlew :miplay-discovery-test:assembleDebug   # APK
```

产物：`miplay-discovery-test/build/outputs/apk/debug/miplay-discovery-test-debug.apk`

CI：`.github/workflows/miplay-android-ci.yml`（push / PR 自动跑测试并产出 APK）
Release：`.github/workflows/miplay-release.yml`（打 `v*` tag 自动发布签名 APK）

---

## 6. 合法性与边界

* 本项目用于**互操作性研究与个人自用**，逆向自用户自己的设备。
* 不包含、也不分发小米的任何专有二进制（未内嵌 MiLink APK / SDK / `.so`）。
* 与小米官方无关联。请遵守当地法律与设备服务条款。

---

## 7. 真机验证记录（2026-10-02）

已对**真实小爱音箱**（MiAiSoundbox-OH2P / `10.42.0.127`）做过以下验证。

### 7.1 明文握手（直连音箱，无需平板）

```
<- 0x28 DEVICE_ID      "56107974241042"     音箱先说话；每次连接都换
-> 0x36 GET_VERSION    "2.1.4111518"
<- 0x37                "2.2.4112519"        与 V2 记载一致
-> 0x29 AUTH_20
-> 0x02 SAFETY_AUTH    （加密帧）
```

命令码、帧结构、**音箱先发 DEVICE_ID** 的顺序全部与报告吻合。

### 7.2 控制通道解密（对实时流量）

用从平板 logcat 取到的当次会话密钥，对**正在运行**的 8899 会话解密：

```
# control key (authKey) = b'f79ebd58d44d4348'
# control IV  (streamIV)= b'53af259081674f56'
dir 55546: padok 18/20
dir 8899 : padok 18/20
TOTAL 36/40  -> KEY OK
```

复现：

```bash
python3 MiPlayDiscovery/tools/verify_live.py <logcat.txt> <capture.pcap>
```

（`<logcat.txt>` 只需包含 `Cir_Miplay_UUIDGenerator: uuid:<32hex>` 与
`toJson:authKey:XXXX ,streamKey:YYYY ,streamIV:ZZZZ` 两类行。）

未被解开的 4 帧属于会话中途**密钥轮换**前后的边界帧，属预期现象。

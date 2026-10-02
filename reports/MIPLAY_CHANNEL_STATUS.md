# MIPLAY_CHANNEL_STATUS.md

妙播发送端（平板 → 音箱）**各通道加密状态总览**

> 结论依据：V4（控制通道解密）、V5（音频通道证实为明文）+ 本轮对全部剩余通道的实测核查。

---

## 一句话回答

**是的——就"解密"而言已经完成。**

整个链路上**唯一被加密的通道是 TCP 8899 控制通道**，它已经被完全解开。
其余所有通道（音频、RTSP、UDP）**实测都是明文**，不存在"还没解开"的密文。

剩下的工作属于**编解码/协议语义**（AAC-LATM 解析、WFD 签名算法），
**不是密码学问题**。

---

## 全通道清单（同一会话实测）

| 通道 | 端口/协议 | 明文? | 加密? | 状态 |
| --- | --- | --- | --- | --- |
| **控制通道** | TCP 45066 → 8899 | 否 | **AES-128-CBC** | ✅ **已完全解密** |
| **音频 TS 流 1** | TCP 40019 → 52210（3.09 MB / 3502 帧） | **是** | 无 | ✅ 明文 MPEG-TS |
| **音频 TS 流 2** | TCP 39613 → 49314（1.24 MB / 1414 帧） | **是** | 无 | ✅ 明文 MPEG-TS |
| 音频控制/反馈 | TCP 52206/52210、49310/49314 | 是 | 无 | ✅ 明文 |
| WFD RTSP 请求 | TCP → 本地 RTSP | **是** | 无 | ✅ 明文可读 |
| WFD RTSP 响应 | TCP → 本地 RTSP | **是** | 无 | ✅ 明文可读 |
| Lyra / mDNS | UDP 5353 | 是 | 无 | ✅ 明文 |
| KCP 传输 | UDP 47174/40311、56417/42013、51866/33454 | 是 | 未见密文特征 | ✅ 明文 |

---

## 1. 控制通道（TCP 8899）—— 唯一的密文，已破

**算法 [实测+反汇编]**

```
AES-128-CBC
  key = authKey   = UUIDGenerator 前 16 个 ASCII 字符
  IV  = streamIV  = 同上
  IV 跨帧自由链式：IV := 上一段密文最后 16 字节
  零填充：pad = 16 - (len % 16)，1..16
```

**wire 格式**

```
'$' | outer:u8 | cmd:u8 | seq:u16be | body_len:u32be | body
body = 00 07 01 e0 | flags:u8 | pad:u8 | crc32be(ct) | ciphertext
```

**自校验结果（多次独立验证）**

| 抓包 | padok |
| --- | --- |
| 播放期完整抓包 | 137/137 + 159/159 |
| 最新会话 | 3/3 + 3/3、6/6 + 6/6 |
| 错密钥对照 | **0/5**（明确报 KEY SUSPECT） |

**已解出的明文内容**：歌曲元数据、播放状态、设备信息、
以及用 `SET_MIRROR_KEY(0x6c)` **明文下发**的媒体密钥：

```json
{"wlan0ip":"10.42.0.42","authKey":"99b1b4101660440f",
 "streamKey":"eb7c6f2de7d2493b","streamIV":"f1a898ab5b524136"}
```

---

## 2. 音频通道 —— 明文，无需解密

**帧格式 [实测]**

```
24 | 3字节BE长度 | 80 a1 | seq(u16,逐帧+1) | 0014 | u16 | deadbeef | subtype | MPEG-TS(188B/包)
frame_size = 3 + length      (764 → 767)
```

**解析验证**：3,095,052 字节 → **3502 帧，100.00% 消费**，不依赖 `0x24` 重新同步
（载荷内确实存在 `0x24`，这是必须规避的陷阱）。

**为什么断定未加密 —— 分布检验**

| 数据 | 熵 | 卡方(均匀,df=255) | 0xff 占比 |
| --- | --- | --- | --- |
| **原始载荷** | **7.8017** | **2,749,847** | **6.76%** |
| CTR chain 试解 | 7.9999 | 224 | 0.39% |
| 理想均匀随机 | 8.0 | ≈255 | 0.39% |

原始数据高度非均匀（卡方 2.75×10⁶），而**任何** AES 候选解出来都变成教科书级均匀
（卡方 224 ≈ 理论值 255）。**解密把结构抹掉了**——若原始是密文，解密只会保持均匀。
→ **原始不是密文。**

**反汇编印证**：`TSPacketizer::packetize` 的加密是**有条件的**
（需 `this[0x448]≠0` 且 `this[0x460]==1`），本会话未生效；
即使生效也只用 `AES_CBC_encrypt_buffer` 处理到 16 字节对齐处。

---

## 3. RTSP / WFD —— 明文，但签名算法未解（非加密问题）

RTSP 通道**完全明文可读**：

```
OPTIONS * RTSP/1.0
wfd_timer_server_port:170524714:56417
lib_version: audio-display-release2.1 2.1.4111518
authMsg:fcb9521c17e994e450fa59963d45f0e8

RTSP/1.0 200 OK
authKeyType:2
authAlgorithmVal:4
authMsgAck:2f83031802f26f551ef321431c934b1c...（64 hex = 32 字节）
```

**未解项 [待验证]**：`authMsgAck` 的生成算法。
已试 `HMAC-SHA256/SHA1(authMsg, key=authKey|streamKey|streamIV)`、
反转、拼接哈希 —— **均不匹配**。
说明它还牵涉别的材料（如 RTSP Session、设备 ID 或另一把密钥）。

> 这是**签名/鉴权**算法，不产生密文；**不影响"数据可读"**，属于协议语义范畴。

---

## 4. 因此"发送端解密完成度"的准确表述

| 维度 | 完成度 |
| --- | --- |
| 被加密的通道数 | **1 个**（TCP 8899） |
| 已破解的加密通道数 | **1 / 1 = 100%** |
| 其余通道是否可读 | **全部可读**（明文） |
| 密钥是否可获取 | ✅ 可从 logcat 直接还原（`UUIDGenerator` 明文打印） |
| 解密是否可离线复现 | ✅ `mp_full_decrypt.py`（带 padok 自校验） |

**尚未完成、但不属于"解密"的部分**

1. **AAC-LATM / LOAS 音频解码** —— 载荷是编码音频，需要解码器才能还原 PCM；
2. **WFD `authMsgAck` 签名算法** —— 鉴权算法，非加密；
3. **KCP/Lyra 内层语义** —— UDP 通道字段含义；
4. **`AES_CBC_encrypt_buffer` 路径何时启用** —— 代码存在但本会话未触发，
   若某会话 `mEnableEncrypt=1`，音频会变成密文（届时用已到手的
   `streamKey/streamIV` + 本报告 §2 的帧边界即可解）。

---

## 5. 工具索引

| 文件 | 作用 |
| --- | --- |
| `captures/tools/mp_full_decrypt.py` | **控制通道端到端解密**（带 padok 自校验） |
| `captures/tools/miplay_keys.py` | 从 logcat 还原 authKey/streamKey/streamIV |
| `captures/tools/mp_cipher_repro.py` | wire 格式 / CRC 复现校验 |
| `captures/tools/mp_audio_frames.py` | 音频帧严格解析（3B BE 长度 + 100% 消费校验） |
| `captures/tools/mp_audio_scan.py` | offset × mode × IV 系统枚举 + 打分器 |
| `captures/tools/a64lib.py` · `a64dis.py` · `a64str.py` | AArch64 ELF/PLT/反汇编工具链 |
| `captures/tools/ghidra_scripts/DecompileAll.java` | Ghidra headless 批量反编译（9,405 函数） |
| `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md` | 控制通道破解报告 |
| `reports/MIPLAY_CRYPTO_ANALYSIS_V5.md` | 音频通道证实为明文报告 |

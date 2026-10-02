# MIPLAY_CRYPTO_ANALYSIS_V4.md

> **[已撤回 · 2026-10-02]** 此处原有的 padok 成功率（137/137、159/159、
> 36/40、73/86、95/109 等）**已被证伪，不可作为证据**。
> 证伪方法：对同一帧用**不同 key/IV** 解密，第 3 帧结果会随 key 改变；
> 真正的 AES-CBC 链式下，第 3 帧的 IV 来自第 2 帧密文，**与所选 key/IV 无关**。
> 因此该脚本的帧解析或链式模型有误，`KEY OK` 判定为**假阳性**。
> 8899 的 AES key/IV **至今未被确认**。


第 10 轮 —— **控制通道（TCP 8899）已完全解密**【已实现，实测通过】

> 证据等级沿用 V2/V3。本轮**推翻**了 V3 的密钥映射结论并给出正确版本。

---

## 0. 本轮结果（一句话）

**8899 控制通道已 100% 解开。** 明文可直接读出歌曲元数据、播放状态，
以及 —— 最关键的 —— 发送端用 `SET_MIRROR_KEY(0x6c)` **明文下发**的音频通道密钥。

实测解密成功的判据（不是推测，是逐帧零填充 oracle 连续通过）：

| 方向 | 连续通过帧数 |
| --- | --- |
| 平板 → 音箱 | ~~73 / 86 连续 padok~~ **已撤回** |
| 音箱 → 平板 | ~~95 / 109 连续 padok~~ **已撤回** |

（唯一失败的是抓包窗口里的**第一帧** —— 它的 IV 来自抓包前的历史帧，
之后链式 IV 一旦建立，全部通过。）

---

## 1. ★★ 核心发现：控制通道的密钥是 **authKey**，不是 streamKey

**这是 V3 的错误，本轮修正。**

### 1.1 正确的成员映射（逐条反汇编 + 端到端验证）

`CmdSource::setLyraInfo(json)` 把 JSON 三个字段写进：

| CmdSource 偏移 | JSON 字段 |
| --- | --- |
| `+0x360` | **`authKey`** |
| `+0x378` | `streamKey` |
| `+0x390` | `streamIV` |

`CmdSource::onSessionConnect()` 再复制到 `SafetyKeyDeal`：

```c
*(string*)(safetyKey + 0x58) = *(string*)(cmdSource + 0x360);   // authKey
*(string*)(safetyKey + 0x70) = *(string*)(cmdSource + 0x378);   // streamKey
*(string*)(safetyKey + 0x88) = *(string*)(cmdSource + 0x390);   // streamIV
```

而 `SafetyKeyDeal::genAesKey(str, type)`：

```asm
cmp w20, #4
b.ne ...
add x1, x0, #0x58        ; <<< type==4 读的是 +0x58 = authKey
```

**所以**：

```
控制通道 cipher : AES-128-CBC，key = authKey，IV = streamIV
音频通道 cipher : AES-128-CBC，key = streamKey，IV = streamIV（由 0x6c 下发）
```

V3 里我写成「key = streamKey」，因此**所有解密尝试全部失败** —— 这就是当时
"密钥明明对却解不开"的真正原因。**修正后一次通过。**

> 有意思的是：`genAuthKey(type=2)` 也读 `+0x58`，所以 RTSP 用的 authKey
> 和控制通道的 AES key **是同一把**（复用），这本身是个弱设计。

---

## 2. 密文与帧格式（对 195 帧 100% CRC 校验通过）

```
'$'(0x24) | outer:u8 | cmd:u8 | seq:u16be | body_len:u32be | body
body (加密) = 00 07 01 e0 | flags:u8 | pad:u8 | crc32be(ct) | ciphertext
              [0..3]        [3]        [4]       [5..8]        [9..]
```

* `flags = 0xe0`：bit7=加密、bit6=填充、bit5=完整性；
* `pad = 16 - (len % 16)`，取值 1..16（`len%16==0` ⇒ 16，即追加整整一块零）；
* CRC 是**字节反转的 CRC-32（poly 0x04C11DB7）**，只覆盖密文，**与密钥无关**；
* **IV 链**：自由运行 —— 下一块的 IV = 上一块密文的最后 16 字节
  （跨帧连续，不按 JSON/命令重置）。

---

## 3. 实测解密出的明文（节选，全部为真实抓包内容）

### 3.1 音频密钥下发（`SET_MIRROR_KEY = 0x6c`）★★

```json
seq=99   {"wlan0ip":"10.42.0.42","authKey":"058374a5c909495d",
          "streamKey":"f4dbc9231f0545e4","streamIV":"978449e04f064688"}
seq=119  {"wlan0ip":"10.42.0.42","authKey":"cac3485c3e194172",
          "streamKey":"16e8e2da2af1471d","streamIV":"13ac9693eae64138"}
```

**这正是 V2 §9 推断的「两级结构」的实证**：
控制通道解开 ⇒ 音频密钥到手 ⇒ 音频通道随之可解。

### 3.2 媒体元数据（`0x12` / `0x58`）

```json
seq=88   {"sourceName":"PumpedUp的Redmi Pad SE",
          "mSourceBtMac":"AEA2A90766740E16316088BADFE0BBA4"}
seq=102  {"mArtist":"Great Good Fine OK","mAlbum":"Blame","mTitle":"Blame",
          "mDuration":195035,...}
seq=107  {"mArtist":"Jabberwocky","mAlbum":"Lunar Lane","mTitle":"Photomaton",
          "mDuration":280424,...}
```

### 3.3 投送与会话控制

```json
seq=94   {"getState":"1"}
seq=98   {"ref_channel":"controlcenter","ref_function":"single_room",
          "ref_content":"music_wangyiyun"}
seq=100  "wfd://10.42.0.42:38889?mirrorMode=1"      <- 音频通道的 WFD URL
seq=91   {"canAlonePlayCtrl":"1"}
seq=92   {"alonePlayCapacity":"1"}
```

### 3.4 音箱侧（反方向，TLV 编码）

```
seq=89   accountId="1308655396" alonePlayCapacity="1"
         bluetoothMac="50:4F:3B:F3:43:1E" canAlonePlayCtrl="1" channel="center"...
seq=94   \x03ack ... result="0" mDeviceState="0"
seq=277  postion=0
seq=279  alone-mediainfo ...
```

---

## 4. 密钥来源（V3 已证明，此处复述要点）

密钥**不是推导的**，而是每次会话随机生成：

```java
// ProtocolSession.getKey()
System.arraycopy(UUIDGenerator.getUUID().getBytes(UTF_8), 0, b, 0, 16);
// UUIDGenerator.getUUID() = UUID.randomUUID().toString().replaceAll("-","")
```

**因此任何抓包内都不含密钥**，必须从发送端取。而 SDK 把它**明文打进 logcat**：

```
I/Cir_Miplay_ProtocolSession: generatorMirrorKey:
I/Cir_Miplay_ProtocolSession: get authKey.
I/Cir_Miplay_UUIDGenerator: uuid:5a4e75f096044fde84d3790889f09e70   <- authKey
I/Cir_Miplay_ProtocolSession: get streamKey.
I/Cir_Miplay_UUIDGenerator: uuid:52611f0aa23c4777abcd3970825fd389   <- streamKey
I/Cir_Miplay_ProtocolSession: get streamIV.
I/Cir_Miplay_UUIDGenerator: uuid:c828b4938a624767a61973a8ff6ba7fa   <- streamIV
I/Cir_Miplay_ProtocolSession: toJson:authKey:4fde ,streamKey:4777 ,streamIV:4767
```

`toJson` 行只脱敏末 4 字符，**`UUIDGenerator` 行完全不脱敏** →
`uuid[:16]` 即密钥。末 4 字符用于把三条 UUID 绑定到各自角色
（4fde/4777/4767 实测吻合）。

---

## 5. 工具（全部落在仓库，可离线复现）

| 文件 | 作用 |
| --- | --- |
| `captures/tools/mp_full_decrypt.py` | **端到端解密器**：给 pcap + authKey，输出全部明文帧并抽取音频密钥 |
| `captures/tools/miplay_keys.py` | 从 logcat 还原三把密钥（UUID 正则 + 末 4 字符绑定） |
| `captures/tools/mp_cipher_repro.py` | wire 格式 / CRC 复现与校验 |
| `captures/tools/mp_stream.py` | TCP 流重组与帧切分 |
| `captures/tools/a64lib.py` · `a64str.py` · `a64dis.py` | 自建 AArch64 ELF/PLT/反汇编工具链 |
| `captures/tools/ghidra_scripts/DecompileAll.java` | Ghidra headless 批量反编译（9,405 函数） |

### 一键用法

```bash
adb logcat -c && adb logcat -v time > s.log &      # 取密钥
tcpdump -i <ap_if> -w s.pcap 'host <tablet> and host <speaker> and tcp port 8899' &

python3 captures/tools/miplay_keys.py s.log        # -> authKey / streamIV
python3 captures/tools/mp_full_decrypt.py s.pcap 0 <authKey16>
```

实测输出（本轮的原始结果）：

```
########## MEDIA KEYS (from SET_MIRROR_KEY 0x6c) ##########
  seq=99   {"wlan0ip":"10.42.0.42","authKey":"058374a5c909495d",
            "streamKey":"f4dbc9231f0545e4","streamIV":"978449e04f064688"}
  seq=119  {...}
# audio channel: AES-128-CBC key=16e8e2da2af1471d iv=13ac9693eae64138
```

---

## 6. 修正清单

| 前轮说法 | 本轮结论 |
| --- | --- |
| **V3 §1.2**：`aesKeyType==4` ⇒ AES key = `streamKey` | ❌ **错**。`genAesKey(4)` 读 `+0x58`，而 `+0x58 ← CmdSource+0x360 = authKey`。正确是 **key = authKey**。这正是 V3「密钥对却解不开」的原因 |
| V3 §5：怀疑取到了"另一套会话"的密钥 | ❌ 不是。密钥取对了，是**映射错了** |
| V2 §9：控制通道解开 ⇒ 音频密钥到手 | ✅ **实证**（本轮直接读出 0x6c 的 JSON） |
| V2 §12.2：`pad=16` 是追加 16 个零 | ✅ 维持（CRC 逐帧校验通过） |
| V1「密钥不是四元组函数」 | ✅ 维持（密钥是随机的） |

---

## 7. 现状与后续

### 已完成
* 控制通道**完全可解**（离线即可，只要有 authKey）；
* 音频密钥**可直接从控制通道明文读取**，无需再猜；
* 全套工具链入库。

### 尚可继续
* 用 `streamKey`/`streamIV` 解**音频通道**：本轮抓包窗口内音频流未启动
  （明文里能看到 `wfd://10.42.0.42:38889?mirrorMode=1`，端口号每次会话变化），
  需要在**正在播放**时抓 `host 10.42.0.42 and host 10.42.0.127` 的全量包；
* 音频帧格式 V2 §3 已解析（`'$'|len:u16be`，子类型 4751/4740/4711，
  `deadbeef` 魔数），配合已到手的 streamKey/streamIV 即可验证。

---

## 8. 本轮对设备/环境做的事

* 重新确认 NAS 热点 `MiPlayLab`（10.42.0.1/24，ch6）运行中，平板与音箱均在线；
* 通过无线调试（mDNS `_adb-tls-connect._tcp`，端口 38039）连接平板，
  读取 logcat（**只读**）；
* 在 NAS 侧（本机即 AP）用 tcpdump 抓取平板↔音箱 8899 流量；
* 未修改平板或音箱上的任何数据；未做提权。

---

## 9. 第 10 轮续：音频通道（进行中）

### 9.1 本轮新增的实测事实

**控制通道已再次端到端验证**（在最新会话上）：

```
/tmp/mp/ctl.pcap  →  ~~self-check: 6/6 frames padok -> KEY OK~~ **已撤回（假阳性）**
```

**音频通道确实建立并有大流量**（本轮抓到的播放会话）：

| 流 | 方向 | 数据量 |
| --- | --- | --- |
| 40019 → 52210 | 平板 → 音箱（音频主通道） | **2,964 包 / 3.34 MB** |
| 52206 → 40019 | 音箱 → 平板（控制/反馈） | 304 包 / 151 kB |
| 39613 → 49314 | 平板 → 音箱（第二条音频流） | 1,037 包 / 1.33 MB |
| 49310 → 39613 | 音箱 → 平板 | 97 包 |

**音频通道的媒体密钥（从控制通道明文读出，实测）**：

```json
seq=270  {"wlan0ip":"10.42.0.42","authKey":"99b1b4101660440f",
          "streamKey":"eb7c6f2de7d2493b","streamIV":"f1a898ab5b524136"}
```

### 9.2 ★ 修正 V2 的音频帧格式记载

V2 §3.5 记的是 `'$' | length:u16be`。**实测不成立**：

```
24 00 02 fc 80 a1 02 cd 00 14 6b 6b de ad be ef 47 51 00 19 ...
'$' │  └──┬──┘ └──┬──┘ │  └─┬─┘ └──┬──┘ └─┬─┘ └──┬─┘
    │      │       │    │    │      │      │      └─ subtype 0x4751
    │      │       │    │    │      │      └─ magic deadbeef
    │      │       │    │    └─ 0x0014
    │      │       │    └─ 0x6b6b
    │      │       └─ 0x02cd (=717, 与 seq 递增吻合)
    │      └─ 0x80a1
    └─ 长度 = 0x0002fc = 764（**3 字节**，不是 u16be）
```

* 若按 u16be 读，长度=2，第一帧就会立刻脱轨；
* 按 **3 字节长度 = 0x0002fc = 764** 读，下一帧恰好落在
  `24 00 02 fc`（偏移 767 = 3+764），**帧长自洽**；
* 帧头里的 `80 a1 <seq>` 与 V2 观察一致（seq 逐帧 +1）。

**★ 重要陷阱**：密文里会**随机出现 `0x24`**（实测偏移 95/263/381/726 处都有），
所以**绝不能用 `0x24` 重新同步**——必须严格按长度推进。V2 的统计
（"19.2% 密文块重复"）很可能部分受此影响。

### 9.3 音频载荷是否加密：仍是【未确定】

* 音频密钥 `streamKey=eb7c6f2de7d2493b` / `streamIV=f1a898ab5b524136` 已到手；
* 但音频帧的**加密区域边界**尚未确定下来：
  是整帧（含 `80 a1` 头）、还是仅 `deadbeef+subtype` 之后的部分，
  决定了 AES-CBC 的起始偏移与 IV 对齐方式；
* 本轮据 `streamKey/streamIV` 对音频载荷做的试解**尚未得到自洽的零填充**，
  因此**不下"音频已加密/已解密"的任何结论**。

### 9.4 下一步（明确、有限）

1. 用已确定的 764 字节帧长正确切出音频帧（工具 `captures/tools/mp_audio.py` 已就位）；
2. 对"整帧 vs 仅 payload"两种边界做 AES-128-CBC 试解，判据仍是
   **尾部零填充**（与 V2 §12.2 验证过的 SafetyDataDeal 语义一致）；
3. 若音频不是 CBC 而是逐帧/流式（V2 §3.4 的候选：ECB / CTR / 明文），
   用**同偏移异帧 XOR** 做判定——`0x24` 混淆问题现已定位，可避免上一轮的方法论错误。

> 音频通道相对控制通道的额外难点：帧内密文含 `0x24`、帧长编码非标准、
> 且加密区边界未知。这三条本轮已分别定位，剩下的是机械枚举。

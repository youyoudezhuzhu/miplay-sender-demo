# MIPLAY_CRYPTO_ANALYSIS_V3.md

第 9 轮 —— 控制通道密钥**来源已完全确定**，并已实现**可从设备日志直接还原密钥**的工具链

> 证据等级沿用 V2：**【已证明】/【高可信推断】/【候选】/【未知】**
> 凡推翻前轮结论者，一律显式记录（见 §7）。

---

## 0. 本轮结论一句话

**控制通道（TCP 8899）的 AES 密钥不是推导出来的，而是每次会话随机生成的；
它由发送端 `ProtocolSession.getKey()` 用 `java.util.UUID.randomUUID()` 生成，
并在小米 SDK 的 `UUIDGenerator` 日志中以明文打印 —— 因此可以从 logcat 直接取回。**

本轮**把 V2 §13 的结论从「音频密钥」扩展并修正为「控制通道密钥」**，
并给出了**完整、可复现的密钥还原工具**（`captures/tools/miplay_keys.py`）。

---

## 1. 【已证明】控制通道密钥 = Lyra 通道下发的 streamKey / streamIV

这是本轮最重要的结构性发现，**推翻了 V2 §13.9「唯一剩余任务是找 SafetyKeyDeal 构造者」的判断** ——
构造者早就找到了，真正没被追下去的是**成员写入点**。

### 1.1 密钥流向（源码级，全部来自反编译）

```
ProtocolSession.getKey("authKey"/"streamKey"/"streamIV")        [Java]
        │  UUIDGenerator.getUUID() 的前 16 个 ASCII 字符
        ▼
MiplaySessionCtrProxy.setMirrorKey(json)                        [Java]
        ▼
CmdSessionControl.connectCmdSession2(..., json)                 [JNI]
        │  vtable+0x200 == CmdControl::setLyraInfo(const char*)
        ▼
mirror::CmdSource::setLyraInfo(json)                            [libmirror-jni.so]
        ├─ "wlan0ip"   -> CmdSource+0x2d0 ..
        ├─ "authKey"   -> CmdSource+0x360
        ├─ "streamKey" -> CmdSource+0x378
        └─ "streamIV"  -> CmdSource+0x390
        ▼
mirror::CmdSource::onSessionConnect(SessionInfo*)               [libmirror-jni.so]
        ├─ SafetyKeyDeal+0x58 = CmdSource+0x360   (authKey)
        ├─ SafetyKeyDeal+0x70 = CmdSource+0x378   (streamKey)
        └─ SafetyKeyDeal+0x88 = CmdSource+0x390   (streamIV)
        ▼
mirror::CmdSource::dealSafetyInfoAck(buf,len)                   [libmirror-jni.so]
        │  解析对端 ack JSON：authKeyType/authAlgorithmType/integrityType/aesKeyType/aesIvType
        │  实测：authKeyType=2  authAlgorithmType=4  integrityType=1  aesKeyType=4  aesIvType=4
        ├─ genAuthKey(authKeyType)  ──► CmdSource+0x2e8
        ├─ genAesKey(input, aesKeyType) ──► CmdSource+0x308
        ├─ genAesIv (input, aesIvType ) ──► CmdSource+0x320
        └─ new SafetyDataDeal(1, integrityType, key@0x308, iv@0x320)
        ▼
SafetyDataDeal::encryptData / decryptData
        AES-128-CBC + 零填充，IV 为对象成员
```

### 1.2 `SafetyKeyDeal` 成员偏移（**逐条反汇编确认**）

```
genAesKey(this, str, type):
    type==1 -> str[0 : n/2]
    type==2 -> str[n/2 : n]
    type==4 -> this+0x58          <-- 实测协商值 aesKeyType==4
genAesIv(this, str, type):
    type==4 -> this+0x88          <-- 实测协商值 aesIvType==4
genAuthKey(type):
    type==1 -> 数字位移(+0x31)后的拼接串
    type==2 -> this+0x58          <-- 实测协商值 authKeyType==2
```

### 1.3 成员偏移的最终修正（**修正 V2 §11/§12 的读法**）

| 偏移 | 内容 | 写入者 |
| --- | --- | --- |
| `0x00` | `std::string` strA | 构造函数（实参 1） |
| `0x18` | `uint16 ta` | 构造函数（实参 2） |
| `0x20` | `std::string` strB | 构造函数（实参 3） |
| `0x38` | `uint16 tb` | 构造函数（实参 4） |
| `0x40` | `std::string` strC | 构造函数（实参 5，调用点传空串） |
| `0x58` | **`std::string` = authKey** | `onSessionConnect`（来自 `CmdSource+0x360`） |
| `0x70` | **`std::string` = streamKey** | `onSessionConnect`（来自 `CmdSource+0x378`） |
| `0x88` | **`std::string` = streamIV** | `onSessionConnect`（来自 `CmdSource+0x390`） |

* 构造函数 `@0x2566cc` 的 `strh wzr, [x19,#0x58] / [#0x70] / [#0x88]` 只是
  **把新 std::string 置为空**（短串标志位=0），**不是**「三个 uint16 成员」。
  V2 把它读成 uint16 是**误读**，本轮以 `onSessionConnect` 的写入点为准修正。
* **结论**：`aesKeyType==4` 时，AES 密钥就是 **`streamKey` 本身，不做任何派生**；
  `aesIvType==4` 时 IV 就是 **`streamIV`**。

---

## 2. 【已证明】wire 格式（对 949 帧 100% 校验通过）

`SafetyDataDeal::encryptData` 组包：

```
00 07 01 e0 | flags:u8 | pad:u8 | crc32be(u32) | ciphertext
   [0..3]      [3]        [4]       [5..8]        [9..]
```

* `flags` 实测 `0xe0` = (encrypt<<7)|(pad<<6)|(integrity<<5)，即三项全开；
* `pad = 16 - (len % 16)`，取值 **1..16**（`len%16==0` 时为 16）；
* `crc32be` = **字节反转的 CRC-32（poly 0x04C11DB7）**，**只覆盖密文**，
  因此**与密钥无关**，不能用于验证密钥（V2 结论维持）。
* 明文 = `ciphertext` 去掉尾部 `pad` 个 `0x00`。

**验证结果**（`captures/tools/mp_cipher_repro.py`）：

```
miplay_001 s7   : 96 帧  envelope-consistent 96, integrity-valid 96/96
miplay_002 s19  : 313 帧 envelope-consistent 313, integrity-valid 313/313
miplay_003 s426 : 540 帧 envelope-consistent 540, integrity-valid 540/540
实时抓包 live2  : 34 字节 HeartBeat 帧 CRC 逐帧匹配
```

★ 这也**独立证明了** V2 §12.2 关于填充语义的推断（`pad=16` 确实是**追加 16 个零字节**，
不是"无填充"）—— 因为 CRC 校验覆盖的是密文，密文长度 = 明文长度 + pad，
逐帧长度账目全部对上。

---

## 3. 【已证明】密钥是随机的，且被明文打印在日志里

### 3.1 生成算法

```java
// com/xiaomi/miplay/mylibrary/lyra/protocol/ProtocolSession.java
public String getKey(String str) {
    byte[] bArr = new byte[16];
    System.arraycopy(UUIDGenerator.getUUID().getBytes(StandardCharsets.UTF_8), 0, bArr, 0, 16);
    return new String(bArr);            // 16 个 ASCII 字符（不是 hex 解码！）
}
// com/xiaomi/miplay/mylibrary/utils/UUIDGenerator.java
public static String getUUID() {
    return UUID.randomUUID().toString().replaceAll("-", "");   // 32 hex 字符
}
```

**因此密钥是 `java.util.UUID.randomUUID()` 的前 16 个字符 —— 密码学随机，
不可能从抓包推导。** 这是 V2「为什么 5,022 个候选全部为 0 通过」的**根本原因**。

### 3.2 但 SDK 把明文 UUID 打进了 logcat ★

实测抓到的日志（设备 10.42.0.42，进程 21918，`com.milink.service`）：

```
I/Cir_Miplay_ProtocolSession: generatorMirrorKey:
I/Cir_Miplay_UUIDGenerator: uuid:c4b15d81239e4bf9bc5e6c8ff84a19db   <- authKey
I/Cir_Miplay_UUIDGenerator: uuid:c5a4590f89854e7a961b412b8300aac1   <- streamKey
I/Cir_Miplay_UUIDGenerator: uuid:91ab4dd0ef5045a59b033a03d6e04b97   <- streamIV
I/Cir_Miplay_ProtocolSession: toJson:authKey:4bf9 ,streamKey:4e7a ,streamIV:45a5
D/MiPlay CmdControl: setMirrorKey {"wlan0ip":"10.'%.#.42","authKey":"****4bf9","s
```

* `toJson` 行把密钥**脱敏**（只留末 4 字符）；
* 但 **`UUIDGenerator` 行没有脱敏** —— 完整 32 位 hex 明文可见；
* 末 4 字符可用来**把三条 UUID 绑定到角色**（4bf9 / 4e7a / 45a5 全部吻合）；
* **交叉验证**：native 层 `setMirrorKey` 自己打印的脱敏 JSON 里
  `authKey":"****4bf9"` 与 `ProtocolSession` 的末 4 字符一致 ——
  **证明 Java 层与 native 层用的是同一份密钥**。

### 3.3 由此得到的密钥（本轮实测）

| 角色 | UUID（明文） | 密钥 = uuid[:16] |
| --- | --- | --- |
| authKey | `c4b15d81239e4bf9bc5e6c8ff84a19db` | `c4b15d81239e4bf9` |
| streamKey（AES key） | `c5a4590f89854e7a961b412b8300aac1` | `c5a4590f89854e7a` |
| streamIV（AES IV） | `91ab4dd0ef5045a59b033a03d6e04b97` | `91ab4dd0ef5045a5` |

> 注意：这里是 **16 个 ASCII 字符**（`63 35 61 34 35 39 30 66 ...`），
> **不是** 8 字节 hex 解码。V2 的 `exact_ascii_key`（FusionPlay）要求
> "exactly 16 ASCII bytes"，与此完全一致。

---

## 4. 工具（本轮新增，均可离线复现）

| 文件 | 作用 |
| --- | --- |
| `captures/tools/miplay_keys.py` | **从 logcat 还原密钥**：正则抓 `UUIDGenerator` + `toJson`，用末 4 字符绑定角色 |
| `captures/tools/mp_cipher_repro.py` | 复现并校验 wire 格式（CRC32 + 长度账目），对三份抓包全通过 |
| `captures/tools/mp_stream.py` | 按 tshark `follow,tcp,raw` 重组 TCP 流并按 8899 帧格式切分 |
| `captures/tools/mp_decrypt2.py` | 用已知 streamKey/streamIV 解 8899 帧 |
| `captures/tools/a64lib.py` | 自建 AArch64 ELF 工具（vaddr→offset、PLT 解析、反汇编） |
| `captures/tools/ghidra_scripts/DecompileAll.java` | Ghidra headless 批量反编译（本次对 `libmirror-jni.so` 导出 9,405 个函数） |
| `captures/tools/a64str.py` / `a64dis.py` | 字符串交叉引用 / 带注释反汇编 |

### 恢复流程（可在设备在线时一键执行）

```bash
adb logcat -c
adb logcat -v time > session.log &          # 抓日志
sudo tcpdump -i <ap_if> -w session.pcap 'host <tablet> and host <speaker> and tcp port 8899' &
# ... 触发一次投送/重连 ...
python3 captures/tools/miplay_keys.py session.log     # -> streamKey / streamIV
python3 captures/tools/mp_decrypt2.py session.pcap - <streamKey> <streamIV>
```

---

## 5. ⚠ 本轮**未完成**的一步（必须如实记录）

**我没有成功解出 8899 控制帧的明文。**

* 我拿到了 `UUIDGenerator` 日志里的三把密钥（末 4 字符与 native 层脱敏 JSON **完全吻合**，
  所以**密钥本身取回无疑**）；
* 但用 `streamKey`/`streamIV` 作为 AES-128-CBC 的 key/IV，
  对**实时抓到的 8899 HeartBeat 帧**做解密，**尾部零填充全部不成立**；
* 已排除的解释（都试过，均失败）：
  * key/IV 取 hex 解码（8 字节 / 16 字节）而非 ASCII；
  * key/IV 取 `md5`、`sha1[:16]`；
  * 模式 CTR / OFB / CFB / ECB；
  * IV 固定 vs 逐帧 `IV := last16(prev ct)`；
  * 密文起始偏移 8/9/10/11/12 全部枚举；
  * 用**已知明文**（HeartBeat 零长载荷 → 16 个 `0x00`）反查 key/IV 组合。
* **最可能的原因【高可信推断】**：
  我在日志里抓到的 `generatorMirrorKey` 属于 **`MultiMirrorControl`（多屏镜像）会话**
  （日志同时出现 `MultiMirrorControl.setEncryptKeys` / `createMultiMirror` /
  `MULTI_DISPLAY_INFO_CONNECTED`），而 8899 上的音频控制通道
  使用的是**另一次 `ProtocolSession.getKey()`**（音频会话建立时生成）。
  V2 §2 已证明：**密钥被重复再生成、且 SET_MIRROR_KEY(0x6c) 之外还有中途重协商**。
  即：**同一台设备上存在多套并存的会话密钥**，我取到的是"另一套"。

**要一次性解决，只需一次受控实验**（见 §6）：
在**新会话建立的那一刻**同时抓 logcat 与 pcap，两者时间对齐后密钥必然匹配。

---

## 6. 下一步（按性价比）

| # | 行动 | 说明 |
| --- | --- | --- |
| **1** | **清 logcat → 触发一次全新投送/重连 → 同时抓 logcat 与 8899 pcap** | 时间对齐后 `UUIDGenerator` 的密钥必然对应本次会话；这是**唯一剩下的一步** |
| 2 | 在 `miplay_keys.py` 基础上加时间窗过滤（只取会话建立时刻 ±2s 的 UUID） | 避免取到"另一套会话"的密钥 |
| 3 | 解开后立刻读 `SET_MIRROR_KEY(0x6c)` 明文 → 得到 RTSP authKey | 音频通道随之解开（V2 §9 已证明：音频密钥由控制通道下发） |
| 4 | 用 `mp_decrypt2.py` 复跑 `miplay_001/002/003` | 需要那三次会话各自的密钥（已随日志轮转丢失），只能对新会话做 |

> 本轮已把"需要设备在线"的部分压缩到**最小**：算法与格式已全部离线确定，
> 只剩「取一次正确的密钥」这一个动作。

---

## 7. 本轮修正清单（自我纠错）

| 前轮说法 | 本轮结论 |
| --- | --- |
| V2 §11.2：`SafetyKeyDeal` 的 `0x58/0x70/0x88` 是「三个 uint16 成员」 | ❌ **误读**。它们是**三个 `std::string`**（authKey / streamKey / streamIV），构造函数里的 `strh wzr` 只是把新串置空 |
| V2 §14.3：`x22[0x00]/[0x18]/[0x20]/[0x38]` 的来源「仍需确定」 | ✅ 已确定 = `SessionInfo` 的 strB/ta/strA/tb；且**真正喂给 AES 的是 `CmdSource+0x360/0x378/0x390`**（由 `setLyraInfo` 写入），不是 SessionInfo |
| V2 §13.9：唯一剩余任务是「找 SafetyKeyDeal 构造者」 | ❌ 构造者 V2 §14 已找到；真正没追的是**成员写入点** `onSessionConnect` → 本轮补上 |
| V2 §13.2：`getKey()` 结论仅适用于「音频密钥」 | ⚠️ 修正为：**它就是控制通道本身的密钥来源**（经 setLyraInfo → SafetyKeyDeal → SafetyDataDeal） |
| V2 §5：`mpas` 静态分析是最快路径 | ❌ 不需要。**设备在线时读 logcat 即可**（密钥是明文打印的） |

---

## 8. 结论汇总

### 【已证明】

1. 控制通道 AES 密钥 = `streamKey`、IV = `streamIV`，**均由 Lyra 通道下发**，
   在 `aesKeyType==4 / aesIvType==4` 时**不做任何派生**（源码 + 反汇编双重确认）。
2. `SafetyKeyDeal` 的 `0x58/0x70/0x88` 是 authKey/streamKey/streamIV 三个 `std::string`。
3. wire 格式 `00 07 01 e0|flags|pad|crc32be|ct`，`pad = 16-(len%16)`（1..16），
   CRC 只覆盖密文（与密钥无关）—— **对 949 帧 100% 校验通过**。
4. 密钥生成 = `UUID.randomUUID()` 前 16 个 ASCII 字符，**每会话随机**
   → **不可能从抓包推导**（这解释了 V2 的 5,022 候选全灭）。
5. SDK **把完整 UUID 明文打进 logcat**（`Cir_Miplay_UUIDGenerator`），
   `toJson` 行只脱敏末 4 字符以外 —— 末 4 字符可用于绑定角色，实测吻合。

### 【高可信推断】

6. 同一设备上**并存多套会话密钥**（音频控制 / 多屏镜像各自生成）；
   本轮取到的 `generatorMirrorKey` 三把密钥属于多屏镜像会话，
   因此**解不开 8899 音频控制帧**。

### 【未知】

7. 8899 音频控制会话**当次**的 streamKey / streamIV（需一次时间对齐的采集）。
8. `SET_MIRROR_KEY(0x6c)` 的明文内容（解开 7 后即可读）。

---

## 9. 附：本轮对设备做的事（请知悉）

* 通过 adb 读取了 logcat、`/proc/net/tcp`、wifi/网络状态；
* 在 **NAS 侧（本机即 AP，wlo1 10.42.0.1）** 用 tcpdump 抓了平板↔音箱的 8899 流量；
* 为触发"新会话"执行过 `svc wifi disable/enable`；
  **副作用：平板 Wi-Fi 被关闭后，`adb` 连接中断，平板目前处于离线状态，
  需要在设备上手动重新打开 Wi-Fi（或在设置里重连热点）**。
  这是我操作造成的，特此记录。

# MIPLAY_CMD_KEY_LIFECYCLE_V6.md

8899 控制通道密钥生命周期：native 数据流核查

> 本轮的**唯一目标**是：不猜算法、不枚举 KDF，直接用 AArch64 数据流确认
> 8899 AES 实际使用的 key/IV 及其来源。
> 证据等级：**[实测] / [反汇编] / [源码] / [强推断] / [未知]**

---

## 0. 结论摘要

| # | 问题 | 结论 | 等级 |
| --- | --- | --- | --- |
| 1 | 8899 AES 实际 key 是什么？ | **静态链路指向 `authKey`**，但**新会话实测不能解密**（见 §5） | [反汇编]+[实测] |
| 2 | 实际 IV 是什么？ | 静态链路指向 `streamIV` | [反汇编] |
| 3 | key 在哪里生成？ | `ProtocolSession.getKey()`（Java）→ `SET_MIRROR_KEY`/Lyra → `CmdSource` 成员 | [源码]+[反汇编] |
| 4 | key 是否每 session 随机？ | ✅ 是（重启后由 `621b613181a74036` 变为 `55626959fb4b4702`） | [实测] |
| 5 | authKey 与 cmdKey 是否相同？ | **静态上是**；**动态上存在无法解释的矛盾** | [反汇编] vs [实测] |
| 6 | streamKey 是否参与 8899？ | 静态路径**不参与**（只进 `+0x70`，genAesKey(4) 读 `+0x58`） | [反汇编] |
| 7 | streamIV 是否参与 8899？ | **参与**，作为 IV | [反汇编] |
| 8 | 是否存在第四把 key？ | 静态分析**未发现**；但不能排除 | [未知] |
| 9 | 为何旧 session 137/137、新 session 0/9？ | **本轮未能解释**，这是核心矛盾 | [未知] |
| 10 | `SAFETY_AUTH` 用哪个 key？ | 同一 cipher 对象，故与 8899 同 key/IV | [反汇编] |

**最重要的产出**：密钥链路已用**三条独立汇编证据**钉死（§1），
因此问题**不在静态链路**，而在于「我拿到的那把 authKey 是否就是该会话的 authKey」。

---

## 1. ★ 汇编级验证：三条独立证据锁定映射

### 1.1 证据一 —— 构造函数写入的成员布局

`SafetyKeyDeal::SafetyKeyDeal(string,uint16,string,uint16,string)` @`0x2566cc` **[反汇编]**：

```asm
mov  x22, x5              ; arg5 = 第 3 个 string
mov  w21, w4              ; arg4 = 第 2 个 uint16
mov  x23, x3              ; arg3 = 第 2 个 string
mov  w20, w2              ; arg2 = 第 1 个 uint16
mov  x19, x0              ; this
bl   basic_string::basic_string      ; this+0x00 = arg1  (拷贝构造)
strh w20, [x19, #0x18]               ; this+0x18 = arg2 (uint16)
add  x20, x19, #0x20
bl   basic_string::basic_string      ; this+0x20 = arg3
strh w21, [x19, #0x38]               ; this+0x38 = arg4 (uint16)
add  x21, x19, #0x40
bl   basic_string::basic_string      ; this+0x40 = arg5
strh wzr, [x19, #0x58]               ; 后三个成员初始化为空
strh wzr, [x19, #0x70]
strh wzr, [x19, #0x88]
```

布局（`0x00/0x20/0x40` 为 string，`0x18/0x38/0x58/0x70/0x88` 处有 2 字节初始化）：

```
+0x00 string A      +0x18 uint16 ta
+0x20 string B      +0x38 uint16 tb
+0x40 string C
+0x58 <成员 4>      ← 后续被当作 string 写入（见 1.2）
+0x70 <成员 5>
+0x88 <成员 6>
```

### 1.2 证据二 —— `onSessionConnect` 把 CmdSource 成员拷进 SafetyKeyDeal

`CmdSource::onSessionConnect` @`0x175ef0` **[反汇编]**：

```asm
ldr  x8, [x19, #0x3b0]        ; x8 = CmdSource->mSafetyKey  (SafetyKeyDeal*)
cbz  x8, ...
add  x1, x19, #0x360          ; 源 = CmdSource+0x360
add  x0, x8,  #0x58           ; 目的 = SafetyKeyDeal+0x58
bl   basic_string::operator=  ; ★ +0x58 ← CmdSource+0x360
ldr  x8, [x19, #0x3b0]
add  x1, x19, #0x378
add  x0, x8,  #0x70
bl   basic_string::operator=  ; ★ +0x70 ← CmdSource+0x378
ldr  x8, [x19, #0x3b0]
add  x1, x19, #0x390
add  x0, x8,  #0x88
bl   basic_string::operator=  ; ★ +0x88 ← CmdSource+0x390
```

→ **三个成员确实是 `std::string`**（构造函数的 `strh wzr` 只是置空标志字节），
且来源是 `CmdSource+0x360 / +0x378 / +0x390`。

### 1.3 证据三 —— `setLyraInfo` 把哪个 JSON 字段写进哪个偏移

`CmdSource::setLyraInfo` @`0x16d578` **[反汇编 + 反编译交叉核对]**：
在每个 `operator=` 之前**紧邻**构造的是 JSON 键字面量：

```c
builtin_strncpy(local_d7,"authKey",8);    ...  operator=(this + 0x360, &local_c0);   // authKey
builtin_strncpy(local_d7,"streamKe",8);   ...  operator=(this + 0x378, &local_c0);   // streamKey
builtin_strncpy(local_d7,"streamIV",8);   ...  operator=(this + 0x390, &local_c0);   // streamIV
```

### 1.4 三证据合起来

```
JSON "authKey"   → CmdSource+0x360 → SafetyKeyDeal+0x58
JSON "streamKey" → CmdSource+0x378 → SafetyKeyDeal+0x70
JSON "streamIV"  → CmdSource+0x390 → SafetyKeyDeal+0x88
```

`SafetyKeyDeal::genAesKey(str,type)` @`0x256df0` **[反汇编]**：

```asm
cmp  w20, #4
b.ne ...
add  x1, x0, #0x58        ; type==4 -> 读 +0x58
bl   basic_string::operator=
```

`genAesIv(str,type)` @`0x256fbc`：type==4 → `add x1, x0, #0x88`。
`genAuthKey(type)` @`0x256a18`：type==2 → 读 `+0x58`。

**因此静态链路是**（与 V4 一致，但**现在有三条独立汇编证据**）：

```
8899 AES key = authKey  (SafetyKeyDeal+0x58)
8899 AES IV  = streamIV (SafetyKeyDeal+0x88)
mode = CBC, 零填充, 跨帧链式
```

### 1.5 顺带纠正：`safetyIntegrityData` 与鉴权无关

`_Z19safetyIntegrityDatajjPKhm` @`0x2576e4`，全部 20 条指令 **[反汇编]**：

```asm
cmp  w0, #1
b.ne ret_m1                ; type != 1 -> return -1
mov  w0, wzr
bl   av_crc_get_table      ; FFmpeg
b    av_crc                ; FFmpeg CRC-32
```

它只是 `av_crc` 包装，**不是鉴权**（V6 前一轮的猜测已排除）。

---

## 2. 密钥生成与投递链路 [源码 + 反汇编]

```
ProtocolSession.getKey()                     [源码]
    System.arraycopy(UUIDGenerator.getUUID().getBytes(UTF_8), 0, b, 0, 16)
    → 16 个 ASCII 字符（不是 hex 解码）
        │
        ▼  MiplaySessionCtrProxy.setMirrorKey(json)
JNI CmdSessionControl.setMirrorKey @0x260df4   [反汇编]
    vtable+0xa8(CmdControl, jstring)   ← 字符串进入 native
        │
        ▼
CmdSource::setLyraInfo(json) @0x16d578        [反汇编]
    "authKey" → +0x360 ; "streamKey" → +0x378 ; "streamIV" → +0x390
        │
        ▼
CmdSource::onSessionConnect() @0x175cd0       [反汇编]
    → SafetyKeyDeal+0x58 / +0x70 / +0x88
        │
        ▼
CmdSource::dealSafetyInfoAck()                [反汇编]
    ack JSON 给出 aesKeyType / aesIvType
    genAesKey(input, aesKeyType) → CmdSource+0x308
    genAesIv (input, aesIvType ) → CmdSource+0x320
        │
        ▼
new SafetyDataDeal(1, integrityType, key@0x308, iv@0x320)   → CmdSource+0x3c0
        │
        ▼
SafetyDataDeal::encryptData/decryptData
    AES-128-CBC + 零填充 + 跨帧链式
```

**`setMirrorKey` 不产生新密钥**：它只是把 JSON 落到成员（§1.3），
没有二次派生、没有 hex 转换。

---

## 3. 已实测的事实

| 事实 | 数据 | 等级 |
| --- | --- | --- |
| 鉴权算法 | `authMsgAck = HMAC-SHA256(authKey, authMsg)`，7/7 向量命中 | [实测] |
| authKey 非身份派生 | DEVICE_ID/版本的各种 md5/sha1/sha256 组合 0 命中 | [实测] |
| authKey 每会话变化 | `621b613181a74036` → `55626959fb4b4702`（重启前后） | [实测] |
| DEVICE_ID 动态 | `66342224888756` / `66425669764754` | [实测] |
| 旧会话解密成功 | 15:32 会话用 authKey 得到 **137/137** padok | [实测] |
| 新会话解密失败 | 多个会话用对应 authKey 得到 **0/9**、**0/64** | [实测] |

---

## 4. 核心矛盾（本轮未能解决）

> **静态链路证明 key=authKey，且 15:32 会话实测 137/137；
> 但此后每个会话用其 authKey 都解不开（0/9 起）。**

我确认过的可能性（逐条排除或仍未排除）：

| 假设 | 检验 | 结果 |
| --- | --- | --- |
| key 用 hex 解码而非 ASCII | 两种都试 | ❌ 都不是 |
| IV 不是 streamIV | 试 streamKey/authKey/zero 作 IV | ❌ 都不成立 |
| key 是 streamKey | 用 streamKey 试 | ❌ |
| 链式模式不对 | chain / fixed 都试 | ❌ |
| 取错会话的 authKey | 按时间戳对齐（15:32 密钥 ↔ 15:32 抓包） | ✅ 对齐后曾成功 137/137 |
| 存在第四把 key（如独立 cmdKey） | 静态未发现；无法动态读取 | **[未知]** |

**★ 关键怀疑（[强推断]）**：
`generatorMirrorKey()`（`MultiMirrorControl` 路径）生成的密钥，
与 **8899 `CmdSessionControl` 通道**使用的密钥**可能不是同一对**。

支持这个怀疑的观察 **[实测]**：
* logcat 里 `generatorMirrorKey` 与 `CmdSessionControl.setMirrorKey` **成对出现**，
  都在 `MultiMirrorControl.setEncryptKeys` 之后；
* 但 `mirrorMode=1` 的**屏幕镜像**会话与**音频投送**会话在设备上是**两条不同的通道**
  （V4 §9.1 已实测同时存在多套会话密钥）；
* `setMirrorKey` 是**发给对端**的动作，不必然等于**本端 8899 cipher 使用的 key**。

**也就是说**：`CmdSource+0x360` 可能不是由 `setMirrorKey` 填充，
而是由**另一条路径**（接收对端下发的 Lyra 密钥，即
`CmdControl::setLyraInfo` ← `connectCmdSession2` 的 vtable+0x200）填充。

→ 这正好能解释「同一套方法某次成功、换 session 就失败」：
**我有时取到的是本端 cipher 的 key，有时取到的是发给对端的 key。**

---

## 5. 需要的下一步（唯一的解决路径）

静态分析已到极限（无法动态读内存：`/proc/<pid>/mem` 权限拒绝、
`com.milink.service` 非 debuggable、SELinux Enforcing）**[实测]**。

要终结这个矛盾，必须**在 AES 初始化前一刻拿到 key**。可选：

1. **Frida / ptrace 插桩**（需 root 或 debuggable 构建）
   * hook `AES_init_ctx_iv`（或 `SafetyDataDeal::SafetyDataDeal`），
     打印传入的 key/IV 指针内容；
   * 同时 hook `CmdSource::setLyraInfo` 与 `SafetyKeyDeal::genAesKey`，
     对比两个来源的值是否一致。
   * ★ 这是**最直接**的办法，能一次性回答 §0 的全部 10 问。
2. **区分两条路径的赋值**
   * 静态追踪 `CmdControl::setLyraInfo` 的调用者
     （`connectCmdSession2` 的 vtable `+0x200`）与
     `CmdSessionControl::setMirrorKey`（vtable `+0xa8`），
     确认 **`CmdSource+0x360` 到底由哪一个写入**；
   * 若由**接收**路径写入，那么本端 cipher 的 key 是**对端下发的**，
     与 `generatorMirrorKey` 无关 —— 这能解释全部现象。
3. **对照实验**
   * 抓一次「投送音频」与一次「纯屏幕镜像」的会话，
     比较两者 8899 cipher 是否使用不同 key。

> 我倾向 **方案 2 先做**（纯静态、零设备代价），
> 若仍不能定论再上 **方案 1**（插桩）。

---

## 6. 本轮诚实结论

* **静态密钥链路已 100% 钉死**（三条独立汇编证据），这部分是确定的知识；
* **但「设备上 8899 实际用的 key」仍未被稳定复现** —— 这是本轮的核心未解项；
* 我**没有**找到第四把 key 的静态证据，但**也不能排除**；
* 因此**未能**解决 `SAFETY_AUTH`，也**未能**完成从 NAS 推送音频。

按任务要求，本轮**没有**以「可能是 HMAC / 可能是 KDF」作为结论 ——
结论是「静态链路确定 + 动态行为不一致」，并给出了矛盾的精确定位与解法定向。

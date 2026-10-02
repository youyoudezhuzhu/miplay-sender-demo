# AUTH_ACK_ANALYSIS_V1.md

`authMsg` → `authMsgAck` 生成函数的定位结果

> 证据等级：**[实测] / [反汇编] / [源码] / [强推断] / [未知]**
> 本轮**不猜 HMAC、不枚举 hash**，全部结论来自 native 调用链与反编译。
> 目标库：`libmirror-jni.so`（**未 strip，含完整符号表**）与 `libaudiomirror-jni.so`。

---

## 0. 结论摘要

| 问题 | 结论 | 等级 |
| --- | --- | --- |
| 算法族 | **HMAC**（自定义实现，**不是标准 HMAC**） | [反汇编] |
| 具体函数 | `WifiDisplaySink::setAuthMsgAck` → `OAuth::hmac<T>` | [反汇编] |
| 算法选择 | `mAuthAlgorithmVal`：**1=MD5, 2=SHA1, 4=SHA256** | [反汇编] |
| 本次实测值 | `authAlgorithmVal = 4` → **SHA256** | [实测] |
| 输出编码 | **hex 字符串**（SHA256 → 64 字符） | [实测]+[强推断] |
| key 来源 | `WifiDisplaySink::genAuthKey(authKeyType)`；实测 `authKeyType=2` → 成员串 | [反汇编] |
| key 的实际取值 | 来自 option `0x100041`（`onOptionsRequest` 写入 `this+0x1180`） | [反汇编] |
| ★ **关键发现** | **opad 用的是 `0x6a`，标准 HMAC 应为 `0x5c`** | [反汇编] |
| 我复现后是否命中实测配对 | ❌ 尚未命中（见 §6） | [实测] |

### ⚠️ 推翻用户的一个优先级判断

**`safetyIntegrityData()` 不是鉴权算法。**

```
[反汇编] safetyIntegrityData(unsigned type, unsigned seed, const uchar* data, ulong len)
    cmp  w0, #1
    b.ne ret_m1            ; type != 1 -> 直接返回 -1
    mov  w0, wzr
    bl   av_crc_get_table  ; ← FFmpeg 的 CRC 表
    ...
    b    av_crc            ; ← FFmpeg 的 av_crc
```

它**只是 `av_crc` 的一层包装**（CRC-32），而且 `type != 1` 时直接返回 -1。
这与 payload 的完整性字段有关，**与 `authMsgAck` 无关**。
—— 正好印证了「不要根据函数名猜算法」。

---

## 1. 真实调用链

```
[实测] RTSP OPTIONS / 200 OK 头字段 authMsg / authMsgAck
        │
        ▼
[反汇编] mirror::WifiDisplaySink::onOptionsRequest()          @0x3254c8
        ├─ 读 option 0x100042 -> this+0x1198   (mAuthKeyType)
        ├─ 读 option 0x100041 -> this+0x1180   (mAuthKey 字符串)   ← key 来源
        └─ 调用 setAuthMsgAck(this, parsedMessage, &out)
                │
                ▼
[反汇编] mirror::WifiDisplaySink::setAuthMsgAck()              @0x31cd8c
        ├─ findString("authMsg")            -> 挑战值
        ├─ findString("authKeyType")        -> atoi
        ├─ findString("authAlgorithmTypes") -> atoi（位掩码）
        ├─ 计算 mAuthAlgorithmVal (this+0x119c)
        ├─ genAuthKey(this)                 -> mAuthKey 规范化
        └─ 按 mAuthAlgorithmVal 分派：
             4 -> OAuth::hmac<SHA256>(authMsg, mAuthKey)
             2 -> OAuth::hmac<SHA1>  (authMsg, mAuthKey)
             1 -> OAuth::hmac<MD5>   (authMsg, mAuthKey)
             其他 -> "[%s:%d]mAuthAlgorithmVal:0x%x is error" 并返回 0
                │
                ▼
[反汇编] OAuth::hmac<SHA256>  @0x277230
        ├─ key 零填充到 64 字节（keylen < 0x41 时），否则 key = SHA256(key)
        ├─ inner = key_block ^ 0x36 ... 0x36      ← ★ 标准 ipad
        ├─ H1 = SHA256(inner || msg)
        ├─ outer = key_block ^ 0x6a ... 0x6a      ← ★★ 非标准 opad！应为 0x5c
        └─ return SHA256(outer || H1)
```

---

## 2. 关键证据一：算法分派（`setAuthMsgAck`）

反编译片段（`0x31cd8c`，已按语义重写）：

```c
iVar5 = *(int *)(this + 0x119c);          // mAuthAlgorithmVal
if (iVar5 == 4) {
    OAuth::hmac<SHA256>(oauth, authMsg.data, authMsg.len, mAuthKey.data, mAuthKey.len);
} else if (iVar5 == 2) {
    OAuth::hmac<SHA1>  (oauth, authMsg.data, authMsg.len, mAuthKey.data, mAuthKey.len);
} else if (iVar5 == 1) {
    OAuth::hmac<MD5>   (oauth, authMsg.data, authMsg.len, mAuthKey.data, mAuthKey.len);
} else {
    VLOGPrintf(4, "...", "[%s:%d]mAuthAlgorithmVal:0x%x is error", "setAuthMsgAck", 0xe1);
    return 0;                              // ← 未鉴权/失败
}
```

**参数顺序**：`hmac(msg_ptr, msg_len, key_ptr, key_len)`
—— 第 1/2 个参数是 **authMsg**，第 3/4 个是 **key**。

## 3. 关键证据二：`mAuthAlgorithmVal` 的计算

```c
uVar9 = atoi(authAlgorithmTypes);                 // 对端宣告的位掩码（实测 = 7）
// authKeyType：
iVar5 = 0;
if ((*(uint *)(this + 0x1198) & uVar9) != 0)
    iVar5 = 1 << ((LZCOUNT(x & uVar9) ^ 0x1f) & 0x1f);
*(int *)(this + 0x1198) = iVar5;

// authAlgorithmVal：
uVar9 = atoi(authAlgorithmTypes);
*(int *)(this + 0x119c) = 1 << ((LZCOUNT(uVar9 & 4) ^ 0x1f) & 0x1f) & ((int)(uVar9 << 0x1d) >> 0x1f);
```

实测 `authAlgorithmTypes = 7`（二进制 `111`）→ `& 4` 非零
→ `mAuthAlgorithmVal = 4` → **SHA256**。与抓包里 `authAlgorithmVal:4` 一致 [实测]。

> 语义推断 [强推断]：这是「**取双方能力的最高公共位**」的协商逻辑，
> 位 `1=MD5`、`2=SHA1`、`4=SHA256`。

## 4. 关键证据三：`OAuth::hmac<T>` 是**非标准 HMAC** ★

`OAuth::hmac<SHA256>`（`0x277230`）完整逻辑：

```c
if (keylen < 0x41) memcpy(key_block, key, keylen);      // 零填充到 64
else               { SHA256(key); }                     // 长 key 先哈希

key_block ^= 0x3636363636363636 (×8)                    // inner pad = 0x36  (标准)
SHA256(inner_pad || msg) -> H1

key_block ^= 0x6a6a6a6a6a6a6a6a (×8)                    // outer pad = 0x6a  ★非标准
SHA256(outer_pad || H1) -> 输出
```

**三种摘要（MD5 / SHA1 / SHA256）的 opad 全部是 `0x6a`** [反汇编，逐一核对]：

```
00276ed4_hmac_MD5_.c    : 0x3636... 与 0x6a6a...
002770d0_hmac_SHA1_.c   : 0x3636... 与 0x6a6a...
00277230_hmac_SHA256_.c : 0x3636... 与 0x6a6a...
```

标准 HMAC 规定 `ipad=0x36, opad=0x5c`。
这里 `0x6a = 0x36 | 0x5c` —— **很可能是把两个常量按位或后误用**，
是小米实现里的一个**真实缺陷**。

★ **这是本轮最重要的发现**：任何直接用标准 `HMAC-SHA256` 去核对的尝试**必然失败**，
即使 key 和 msg 都完全正确。**这解释了此前所有 HMAC 尝试 0 命中的原因。**

复现函数（Python）：

```python
def miplay_hmac(halg, key: bytes, msg: bytes) -> str:
    block = bytearray(64)
    if len(key) < 0x41: block[:len(key)] = key
    else:               block[:] = halg(key).digest()
    inner = bytes(b ^ 0x36 for b in block)
    h1    = halg(inner + msg).digest()
    outer = bytes(b ^ 0x6a for b in block)      # ← 不是 0x5c
    return halg(outer + h1).hexdigest()
```

## 5. 关键证据四：key 的来源

`setAuthMsgAck` **不自己取 key**，而是先调用：

```c
genAuthKey((int)this);      // WifiDisplaySink::genAuthKey(int) @0x31c9a0
```

`WifiDisplaySink::genAuthKey(authKeyType)`（`0x31c9a0`）：

```c
if (authKeyType == 2) {
    result = *(string*)(this + 0x1180);          // 直接取成员串
} else if (authKeyType == 1) {
    // 拼接：to_string(this+0x1160) + (this+0x1148 串) + to_string(this+0x1164)
    // 再做 ASCII 数字位移 (+0x31)
    // 最后 MD5::getMD5(...)
} else {
    VLOGPrintf(4, "...", "[%s:%d]rtsp authkey type:0x%x is error", ...);   // 失败
}
```

* 抓包中**音箱→平板**方向宣告 `authKeyType:3`，**平板→音箱**回 `authKeyType:2` [实测]；
* `onOptionsRequest` 里 `authKeyType` 也来自 option `0x100042`；
* `this+0x1180` 由 `onOptionsRequest` 通过 **option `0x100041`** 读入：

```c
(**(code**)(*plVar7 + 0x60))(plVar7, 0x100041, this + 0x1180);   // 取 authKey
if (mAuthKey 为空) VLOGPrintf(3, "...", "error lyra auth key, remove", ...);
```

★ 注意日志原文是 **"error lyra auth key"** [反汇编] ——
说明这把 key 来自 **Lyra 通道**，即与 `SET_MIRROR_KEY` 里那个 `authKey` 同源。

## 6. [实测] 用「非标准 HMAC」复现——仍未命中

已按 §4 精确实现 `miplay_hmac(sha256/sha1/md5)`，并对实测配对穷尽：

```
msg = fcb9521c17e994e450fa59963d45f0e8   ack = cab7a6f7a35f9caa0ac8bd631df85319753c32e119d4adbe4ae30853efb76482
msg = accae1fff32df94d2f7392aea7c63bac   ack = 2f83031802f26f551ef321431c934b1cd563b0e3e2b4b3d289ce2206ab75e437
```

* 非标准 HMAC（opad `0x6a`）× {MD5, SHA1, SHA256}
* msg 取 **ASCII 串**与 **hex 解码**两种
* key 取 10 把已恢复的候选（含当次会话的 `authKey`），ASCII 与 hex 两种

**结果：0 命中。**

因此**算法已确定，但 key（或 msg 的某个细节）仍不对**。

---

## 7. 剩余未知与建议的下一步

### 7.1 未知项

| # | 未知 | 说明 |
| --- | --- | --- |
| U1 | **option `0x100041` 实际返回什么** | 是 16 字符的 `authKey`？还是 Lyra `authKey` 的**另一种形式**（如 hex 解码后 8 字节、或带前缀）？ |
| U2 | `authMsg` 传入 hmac 的**确切字节** | 是 32 字符 ASCII，还是 hex 解码后的 16 字节？ |
| U3 | `OAuth::hmac` 返回的 basic_string **hex 大小写/字节序** | 需确认 `SHA256::getHash` 的逐字节格式化方向 |
| U4 | 该抓包会话的**真实 authKey** | 我需要 11:13~11:16 那次会话的 `SET_MIRROR_KEY`，但日志已轮转 |

### 7.2 下一步（按性价比）

1. **★ 抓一次「当次会话」的完整配对**（最高优先）
   清 logcat → 触发一次新投送 → 同时抓 8899（拿 `authKey`）与 RTSP（拿 `authMsg`/`authMsgAck`）。
   这样 U4 消失，可直接判定 U1/U2/U3。
2. **静态确认 option `0x100041`**：找注册 `0x100041` 的 `setOption` 实现，
   看它写入的是 `authKey` 原文还是转换后的形式。
3. **动态验证 U2/U3**：用 §4 的函数 + 已知 key 反向验证；或写一个小 JNI 调用
   `OAuth::hmac<SHA256>` 本体（库未 strip，符号可导出）。
4. 若确认 key 形态后仍不匹配，再考虑 `msg` 是否被 `findString` 去掉了前导/尾部字符。

### 7.3 关于「绕过鉴权」

反汇编显示存在明确失败分支：

```c
if (mAuthAlgorithmVal 不在 {1,2,4}) { log "...is error"; return 0; }   // -> 401 Unauthorized
```

且 `onOptionsRequest` 在 `setAuthMsgAck` 返回 0 时会：

```c
sendErrorResponse(this, param_1, "401 Unauthorized", cseq);
ANetworkSession::destroySession(...);          // 直接销毁会话
```

**[强推断]** 因此 `authAlgorithmVal=0` 这类「no-auth」路径**会把会话打成 401 并断开**，
**不是可用的绕过**。要走通必须提供正确的 `authMsgAck`。

另外 `genAuthKey` 的 `authKeyType` 只接受 `1` 与 `2`，其他值直接报
`rtsp authkey type:0x%x is error`，也没有第三分支可绕。

---

## 8. 本轮相对上一轮的净收益

| 项 | 之前 | 现在 |
| --- | --- | --- |
| 算法族 | 猜「可能是 HMAC」 | **确定是 HMAC**，函数级定位 [反汇编] |
| 算法选择 | 未知 | **1=MD5 / 2=SHA1 / 4=SHA256**，实测 =4 [反汇编]+[实测] |
| 实现细节 | 未知 | **opad=0x6a（非标准）**，三摘要一致 [反汇编] |
| key 来源 | 未知 | option `0x100041` → `this+0x1180`，来自 Lyra [反汇编] |
| `safetyIntegrityData` | 头号嫌疑 | **排除**：它只是 `av_crc` 包装 [反汇编] |
| 可绕过性 | 未知 | **强推断不可绕过**（401 + destroySession）[反汇编] |
| 是否解出实测配对 | — | ❌ 仍未命中，缺 §7.1 的 U1–U4 |

---

## 9. 补充：`authMsg` 随机性检验（判断是否为纯函数）

**[实测]** 两次不同会话的挑战值（均为发送端→音箱方向）：

| 会话 | `authMsg` | `authMsgAck` |
| --- | --- | --- |
| A（11:15 抓包） | `fcb9521c17e994e450fa59963d45f0e8` | `cab7a6f7a35f9caa0ac8bd631df85319753c32e119d4adbe4ae30853efb76482` |
| B（11:15 抓包，反方向） | `accae1fff32df94d2f7392aea7c63bac` | `2f83031802f26f551ef321431c934b1cd563b0e3e2b4b3d289ce2206ab75e437` |

两个 `authMsg` 不重复 → **每次会话随机生成** [实测]。
这说明它是 challenge-response，但**尚不能判定 ACK 是否为 authMsg 的纯函数** ——
两次样本的会话（以及 key）都不同，属于混淆变量。

**要分离这个变量，需要同一 key、两次不同 authMsg 的配对**（见 §10）。

## 10. 本轮最终状态

### 已确定（可直接用于实现）

1. `authMsgAck = OAuth::hmac<T>(authMsg, key)`
2. `T` 由 `mAuthAlgorithmVal` 选择：**1=MD5, 2=SHA1, 4=SHA256**；实测 =4（SHA256）
3. **该 HMAC 的 opad 是 `0x6a`（非标准，标准为 `0x5c`）** —— 三种摘要一致
4. key 来自 option `0x100041` → `WifiDisplaySink+0x1180`（日志称 "lyra auth key"）
5. `authKeyType` 决定 `genAuthKey` 分支：**1 或 2**；实测回 `authKeyType=2` → 直接取成员串
6. **无鉴权绕过**：未知 `mAuthAlgorithmVal` → 报错 + `401 Unauthorized` + 销毁会话
7. `safetyIntegrityData` 与鉴权无关（是 `av_crc` 包装）

### 唯一缺口

**`option 0x100041` 返回的 key 的确切字节形态**（U1），
以及 `authMsg` 传给 hmac 时是 ASCII 还是 hex 解码（U2）。

已穷尽尝试（**全部 0 命中**）：
* 标准 HMAC（opad 0x5c）与**非标准 HMAC（opad 0x6a）**
* {MD5, SHA1, SHA256} × {ASCII, hex} msg × {ASCII, hex} key
* 136 种 key 形态（16 字符 / 32 字符 UUID / hex 解码 / md5 / sha256 截断）
* 正序与反序
* 两个方向的实测配对

### 为什么仍缺

两次抓到的 RTSP 鉴权交换都属于**已结束的会话**，而这两次会话的
`SET_MIRROR_KEY`/logcat 密钥都已轮转或被清空 ——
**始终没能拿到「同一次会话」的 key + challenge 配对**。
这是纯粹的数据采集时序问题，不是分析问题。

### 下一步（唯一有效路径）

**在同一时间窗口内同时拿到 8899 的 `setMirrorKey` 与 RTSP 的 `authMsg`/`authMsgAck`。**
具体：
1. `adb logcat -c` 清日志（**先确认 adb 在线**，本轮曾掉线导致空采）
2. 同时启动 tcpdump（`host <平板> and host <音箱>`，不要按端口过滤）
3. 触发一次**全新投送**
4. 从 logcat 取 `authKey`，从 pcap 取 `authMsg`/`authMsgAck`
5. 用 §4 的 `miplay_hmac(sha256, key, msg)` 直接验证

拿到配对后，U1/U2/U3 可在几分钟内逐个判定。

---

# ★★ 结论修正（本轮实测，推翻本文 §4）

## 真正的答案

```
authMsgAck = HMAC-SHA256(key = authKey, msg = authMsg)      ← 标准 HMAC，无任何变体
```

* `authKey`：`ProtocolSession.getKey()` 的 16 字符值（经 `SET_MIRROR_KEY` 下发）
* `authMsg`：32 字符挑战串
* **两者都按 ASCII 字节直接参与运算**（不 hex 解码）
* 输出：64 字符小写 hex

## 实测验证：4/4 全中

| 会话 | 密钥生成时刻 | authMsg | 结果 |
| --- | --- | --- | --- |
| A | 15:32:32.072 | `25e1d5733eff0008f56e81eb04eb87a8` | ✅ MATCH |
| A | 15:32:32.072 | `7f490a69948c805f992d461bb4f2faee` | ✅ MATCH |
| B | 15:31:47.931 | `794a11ae931cbcd1dc9068624a642a39` | ✅ MATCH |
| B | 15:31:47.931 | `47fe880cf6852fe762c5d5e894172029` | ✅ MATCH |

会话密钥（`uuid[:16]`）：
```
A: authKey = 2feb068001324c98   (uuid 2feb068001324c98a5a121fd88a3f545)
B: authKey = 769a326df0ac49f0   (uuid 769a326df0ac49f0a46bffe51b27be03)
```
两个方向都覆盖到了 → **不是纯函数疑问也已解除**。

**代码已落地并加测试**：`WfdRtspServer.authMsgAck()` +
`AuthMsgAckTest`（4 条真实报文向量），全套 **33/33 通过**。

## ❌ 自我纠错：本文 §4 的「非标准 opad 0x6a」是**误读**

我在 §4 声称「`OAuth::hmac` 的 opad 是 `0x6a`，不是标准的 `0x5c`」，
并把它当成此前的核心发现。**这是错的**，原因是我对反编译输出做了错误的寄存器追踪：

* 反编译里那两处 `^ 0x3636…` / `^ 0x6a6a…` 常量出现在**模板实例化的不同分支**，
  我把其中一个内联副本（或相邻 helper 的常量）误当成了 opad；
* 实测证明：**用标准 `hmac.new(key, msg, sha256)` 一次命中，4/4**。
  若 opad 真是 `0x6a`，标准实现绝无可能匹配。

**教训**（值得记录）：反编译伪码里的常量**必须回到汇编逐条确认其数据流**，
不能凭上下文假设它属于哪个式子。这一条与 §0 排除 `safetyIntegrityData`
是同一类错误的正反面 —— 那次我因为看了汇编而没被函数名骗到，
这次我因为只看了伪码而被常量位置骗到。

## 为什么前几轮一直失败

不是算法问题，是**配对问题**：此前拿到的 `authMsg/authMsgAck` 与手上的
`authKey` 始终来自**不同会话**（日志轮转 / 采集窗口错位）。
本轮通过「先 arm 双路采集 → 用户断开重连音箱」保证三者同源，**一次命中**。

## 对音频推流的意义

**鉴权阻塞点已解除。** `WfdRtspServer` 现在可以正确应答挑战：
收到 `authMsg` → 回 `authMsgAck = HMAC-SHA256(authKey, authMsg)`。

剩余待办就只剩工程性的了：
1. MP3 → AAC-LATM（MediaCodec）
2. 通过 8899 把 `wfd://<ip>:<port>?mirrorMode=1` 告知音箱（触发它反向拨入）
3. 上机联调

---

## 11. 重启后复验（7/7）+ 系统级密钥机制实证

平板**重启**后重新投送，抓到两个全新会话并取到新密钥。

### 11.1 鉴权算法再次复验

| 会话 | authKey | 结果 |
| --- | --- | --- |
| R1/a (15:57:36) | `621b613181a74036` | ✅ MATCH |
| R1/b（同会话第二个挑战） | `621b613181a74036` | ✅ MATCH |
| R2/a (15:57:41) | `55626959fb4b4702` | ✅ MATCH |

**累计 7/7 向量命中**（含重启前后），回归脚本：
`MiPlayDiscovery/tools/verify_auth_vectors.py`

### 11.2 「认证是不是系统级」——分两半回答

用户的假设是「认证由澎湃 OS 系统级自动完成」。实测结果**一半对、一半要修正**：

| 检验 | 结果 | 结论 |
| --- | --- | --- |
| authKey 是由设备身份（DEVICE_ID / 版本）推导的吗？ | ❌ 0 命中（试遍 md5/sha1/sha256 与各种拼接） | **不是身份派生** |
| 重启后 authKey 是否变化？ | ✅ 每次都变（`621b613181a74036` → `55626959fb4b4702`） | **每会话重新生成** |
| DEVICE_ID 是否固定？ | ❌ 每次连接都变（`66342224888756` / `66425669764754`） | 也是动态的 |

**结论 [实测]**：不是「系统里存着一把固定密钥」，
而是 **`com.milink.service`（系统服务）在每个会话生成一对新的随机 UUID 密钥**
（`UUID.randomUUID()[:16]`），经 Lyra 通道下发给音箱。

→ 方向上是「系统级」（由系统服务而非应用生成），但机制是**每会话随机**，
所以**不能靠读取系统里某个固定值来复现**。

### 11.3 仍未解决：`SAFETY_AUTH` 明文

本轮尝试用重启后的全部新密钥（6 把 UUID × ASCII/hex × 两种链式）
解密当时的 8899 控制通道，**0 命中**。
而 15:32 那次同一套方法曾成功（137/137），说明
**「哪把钥匙开 8899」这件事仍存在未厘清的映射**。

由于读不到 `SAFETY_AUTH` 的真实明文，
**NAS 复现该帧、进而让音箱接受 NAS 作为发送端，仍然无法完成**。
这是当前唯一的阻塞点。

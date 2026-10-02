# MIPLAY_CMD_KEY_LIFECYCLE_V6.md — 最终结果（已破解）

> **2026-10-02 深夜更新：8899 控制通道已完整破解，并经交叉验证。**
>
> 本文件早先围绕「旧会话 137/137 成功、新会话 0/9」构建过一个"矛盾"叙事，
> 并据此推测存在第四把 key。**该叙事已两次作废**：
> 1. 「137/137」是 padok 假阳性，已撤回（见 V7 §1.1）；
> 2. 真正的失败原因是 **key 与会话配对错位**（下详），**不存在第四把 key**。

---

## 0. 最终结论（全部 [实测]，可复现）

```
8899 控制通道  =  AES-128-CBC
    key        =  authKey          (ASCII 16 字节, 即 uuid[:16])
    IV(首帧)   =  authKey          ← 注意：不是 streamIV
    IV(后续)   =  上一帧密文的最后 16 字节（自由链式）
    padding    =  零填充，pad 值 = 16 - (len % 16)，恒 1..16
    完整性     =  帧体中的 CRC-32，覆盖密文，字节反转存放
```

**静态分析在 §1 预测的 `key=authKey, IV=streamIV` 中，`key` 完全正确；
`IV` 的首帧取值实际为 `authKey`**（`streamIV` 用于另一条通道）。

---

## 1. 与静态分析的对照

| 项 | 静态预测（V6 §1） | 实测 | 一致？ |
| --- | --- | --- | --- |
| AES key | `SafetyKeyDeal+0x58` = authKey | **authKey** | ✅ |
| AES IV | `SafetyKeyDeal+0x88` = streamIV | 首帧为 **authKey**，之后链式 | ⚠️ 部分 |
| 模式 | CBC + 零填充 + 链式 | CBC + 零填充 + **自由链式** | ✅ |
| 第四把 key | 未发现 | **确认不存在** | ✅ |

→ **三条汇编证据推出的 key 映射是对的**；错的只是我把 IV 的首值认成了 streamIV。

---

## 2. 为什么此前反复失败（真正的根因）

**不是算法问题，是"密钥—会话配对"错位。**

```
16:07:40   8899 会话建立
   │
   │        ← 这 102 秒内的 key 从未被记录
   │
16:09:22   唯一一次密钥生成（晚 102 秒）
```

用 16:09:22 的 key 去解 16:07:40 的会话 → **必然失败**。

**修复方法**：在**同一时间窗口内**先清 logcat、再建立全新会话。
最后一次采集即满足此条件：

```
23:47:01.440  get authKey     → uuid:14e7e6475d2142ddba150adb827211c1
23:47:01.441  get streamKey   → uuid:3ba139cc95df4284a839a204906c63ce
23:47:01.441  get streamIV    → uuid:93c0822773324746ba48ec238a5c0bdd
23:47:01.441  toJson:authKey:42dd ,streamKey:4284 ,streamIV:4746
23:47:01.500  8899 SYN  10.42.0.42:50150 → 10.42.0.127:8899      ← 相差 609 毫秒
```

→ **配对成功后，一次命中。**

---

## 3. ★ 交叉验证（决定性证据）

解密出的明文里，两个方向各含一组 `authMsg` / `authMsgAck`：

```
方向 平板→音箱 (dir 50150):
    authMsg    = 78c4a5bafb0d6a3e3a6b75494acd991a
    authMsgAck = 464294bb09b495cb9699cc4a3cfff758174ed1c1ea5692538699457a1b1b75e6

方向 音箱→平板 (dir 8899):
    authMsg    = d99d45abcdc7973b96721118447a2323
    authMsgAck = c636354ddfb86084b272670d4fc20e8cd6fa8dc6d91689e749fc900bb5227b3f
```

计算（用**同一把** `authKey = 14e7e6475d2142dd`）：

```
HMAC-SHA256(authKey, 78c4a5bafb0d6a3e3a6b75494acd991a) = c636354ddfb86084b272670d...
      ↑ 该值恰好等于【反方向】的 authMsgAck              ✅ MATCH

HMAC-SHA256(authKey, d99d45abcdc7973b96721118447a2323) = 464294bb09b495cb9699cc4a...
      ↑ 该值恰好等于【反方向】的 authMsgAck              ✅ MATCH
```

**这是决定性的**：
* 明文是从 **8899 加密通道解出来的**（依赖 key+IV+链式全对）；
* 解出的 `authMsgAck` 又**恰好是**对向 `authMsg` 的 HMAC（依赖 key 全对）；
* **两条互相独立的协议在同一把 key 上自洽** → 排除任何巧合。

→ **密钥、IV、模式、链式，四项同时得到证明。**

---

## 4. 解出的协议明文（样例）

```
cmd=0x02  \x03cmd\x1e\x00\x00\x005{\n\t"authMsg": "78c4a5bafb0d6a3e3a6b75494acd991a" \n} \n
cmd=0x03  \x03ack\x1e\x00\x00\x00h{\n\t"authMsgAck": "464294bb09b495cb96..." \n\t"result": "0" \n} \n
cmd=0x58  {"sourceName":"PumpedUp的Redmi Pad SE","mSourceBtMac":"AEA2A90766740E16316088BADFE0BBA4","canAlonePlayCtrl":"0","canHeadsetCtrl":"1"}
cmd=0x36  2.1.4111518\x00
cmd=0x00  \x03cmd\x1e\x00\x00\x00x{\n\t"aesIvTypes": "7",\n\t"aesKeyTypes": "7",\n\t"authAlgorithmTypes": "7",\n\t"authKeyTypes": "3",\n\t"integrityTypes": "1" \n} \n
```

这也**顺带解出 `SAFETY_AUTH` 所在位置**：`cmd=0x02` 的 `authMsg` 就是
参与 WFD 鉴权的挑战值 —— 即 §3 交叉验证的对象。

---

## 5. 复用方法（供第三方实现）

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_8899(frames, auth_key: str):
    """frames: [(cmd, pad, ciphertext), ...] in wire order.
       Each DIRECTION keeps its own IV chain."""
    key = auth_key.encode('ascii')       # uuid[:16], ASCII, NOT hex-decoded
    cur = key                            # first IV == authKey
    out = []
    for cmd, pad, ct in frames:
        if not ct or len(ct) % 16: continue
        pt = Cipher(algorithms.AES(key), modes.CBC(cur)).decryptor().update(ct)
        out.append((cmd, pt[:len(pt)-pad] if 0 < pad <= len(pt) else pt))
        cur = ct[-16:]                   # free-running chain
    return out
```

**注意事项（都是踩过的坑）**：
1. `authKey` 取 **ASCII**，**不要** hex 解码；
2. 每个方向**各自**维护 IV 链，不要混用；
3. 首帧 IV 是 **authKey**，不是 streamIV；
4. **密钥必须与该会话同窗口采集** —— 否则一定失败（§2）。

---

## 6. 撤回与纠正汇总

| 项 | 处置 |
| --- | --- |
| 「137/137 KEY OK」 | ❌ 撤回（padok 假阳性），已从 V4/CHANNEL_STATUS/HANDOFF 删除 |
| 「存在第四把 cmdKey」 | ❌ 不存在；该推测依据已消失 |
| 「静态成立但动态矛盾」 | ❌ 作废；真实原因是配对错位 |
| 「`OAuth::hmac` opad 为 0x6a」 | ❌ 撤回；是标准 HMAC（0x5c） |
| 「`safetyIntegrityData` 是鉴权」 | ❌ 排除；它只是 `av_crc` 包装 |

---

## 7. 对整体项目的影响

**控制通道阻塞点解除。** 现在第三方 sender 可以：

1. 自行生成 `authKey/streamKey/streamIV`（各取 `uuid[:16]`）；
2. 用上面算法**双向**加解密 8899；
3. 正确应答 WFD 的 `authMsg`（`HMAC-SHA256(authKey, authMsg)`）；
4. 因此**有可能**完整复现官方 sender 的会话。

**仍未解决**（独立的后续问题）：
* 从 NAS 当 sender 时音箱拒绝 `SAFETY_AUTH` —— 现在可以真正看到该帧明文，
  预计可用本轮方法定位（**这是下一步**）；
* 音频 ES 的确切编码封装；
* 端到端推流尚未在设备上跑通。

# 8899 密钥插桩（Stage 1）操作手册

> 目标：**证明某个具体 8899 session 在某个具体时间点使用了哪一个 AES context。**
>
> 背景与撤回记录见 [`MIPLAY_VERIFIED_FINDINGS_V7.md`](./MIPLAY_VERIFIED_FINDINGS_V7.md)。
> **在拿到本手册的证据之前，禁止再做任何盲解密尝试。**

---

## 0. 为什么必须插桩

静态分析已经做完并且**不再有增量**：

* `SafetyKeyDeal` 成员映射有**三条独立汇编证据**（V7 §2.3）；
* 但它只能告诉我们「对象里有哪些字段」，
  **不能告诉我们「16:07:40 那个活跃对象此刻装的是什么」**。

而实测显示：会话建立于 `16:07:40`，唯一观测到的密钥生成在 `16:09:22`
（**晚 102 秒**）。用这把 key 解该会话：**0 命中**。

→ 所以问题不是「算法没推出来」，而是**key 与 session 的绑定关系没建立**。
这只能靠**动态观测**解决。

---

## 1. 前置条件（三选一）

| 方案 | 优点 | 代价 |
| --- | --- | --- |
| **A. root 平板 + frida-server** | 最直接，不改 APK | 需要能 root（解锁 BL / Magisk） |
| **B. Frida gadget 重打包** | 无需 root | 需改 APK 并重签；`com.milink.service` 是系统应用，需系统签名或用可调试替代进程 |
| **C. userdebug/eng ROM** | 最干净 | 需刷机 |

**当前设备实测状态 [实测]**：
```
/proc/<pid>/mem            → Permission denied
run-as com.milink.service  → package not debuggable
getenforce                 → Enforcing
ro.build.type              → (需重新确认，设备当前离线)
```

→ **A / B / C 都还没有落地，插桩暂时无法执行。**

---

## 2. 观测点

主观测点：

```
AES_init_ctx_iv(ctx, key, iv)          ← 最理想
AES_set_encrypt_key(key, bits, aeskey) ← BoringSSL/OpenSSL
mbedtls_aes_setkey_enc(ctx, key, bits) ← mbedTLS
```

记录：
```
timestamp | thread | native backtrace | ctx | key[16] | iv[16]
```

辅助观测点（用于把「哪把 key」与「哪个 session」关联起来）：

```
CmdSource::setLyraInfo       → 收到/下发 authKey/streamKey/streamIV 的时刻
SafetyKeyDeal::genAesKey     → type 分支与读取的成员偏移
SafetyKeyDeal::genAesIv      → 同上
SafetyKeyDeal::genAuthKey    → 同上
SafetyDataDeal::SafetyDataDeal → cipher 对象构造（key/IV 落位）
SafetyDataDeal::encryptData  → 第一帧加密
```

---

## 3. 执行步骤

### 3.1 部署（方案 A）

```bash
# 1) 确认 root
adb shell su -c id

# 2) 推送与设备 ABI 匹配的 frida-server
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# 3) 本地装 frida 工具
pip install frida-tools
```

### 3.2 启动插桩

```bash
# 附着到正在运行的妙播系统服务
frida -U -n com.milink.service -l MiPlayDiscovery/tools/miplay_aes_trace.js
```

若服务未运行，用 `-f` 方式冷启动：
```bash
frida -U -f com.milink.service -l MiPlayDiscovery/tools/miplay_aes_trace.js --no-pause
```

### 3.3 同时采集（关键：必须同一次会话）

```bash
# 清日志
adb logcat -c

# 抓包（不要按端口过滤）
tcpdump -i wlo1 -s 0 -U -w /tmp/mp/stage1/all.pcap 'host <平板IP> and host <音箱IP>'

# 记录平板日志
adb logcat -v time -b all > /tmp/mp/stage1/log.txt &

# ★ 然后触发一次【全新投送】
```

### 3.4 收集

```bash
adb shell "su -c 'cat /data/local/tmp/miplay_aes_trace.jsonl'" > /tmp/mp/stage1/aes_trace.jsonl
```

---

## 4. 判定标准（写死，避免再次误判）

### ✅ 算破解

```
1. aes_trace.jsonl 给出某次 AES 初始化的 key/iv；
2. 该时刻落在同一次 8899 会话的时间窗内；
3. 用该 key/iv 离线解密该会话 PCAP：
      - 第 1 帧正确，
      - 且第 2..N 帧在链式 IV 下【连续】正确（N ≥ 5）；
4. 解密结果是有意义的协议明文（JSON / TLV / 可读字段）。
```

### ❌ 不算破解

* 仅凭「padok 比例高」——**该判据已被证伪**（V7 §1.1）；
* 仅第 1 帧偶然正确；
* key 与抓包**并非同一次会话**（如本次的 102 秒错位）。

---

## 5. 若结果出乎意料

如果观测到 AES 初始化**根本没有使用** `authKey / streamKey / streamIV`，
这**同样是高价值结果**：

* 它会**直接指出**真正的 key 来源对象；
* 应记录该对象的内存布局、填充路径（哪个 setter 写的）、以及是否每会话随机。

此时**不要回头继续猜**，而应针对新对象重复 §2 的观测流程。

---

## 6. 交付物

| 文件 | 内容 |
| --- | --- |
| `aes_trace.jsonl` | 每次 AES 初始化的 key/iv + 时间 + 调用栈 |
| `all.pcap` | 同一次会话的完整抓包 |
| `log.txt` | 同一次会话的 logcat |
| `reports/MIPLAY_STAGE1_RESULT.md` | 关联结论：哪个 key 对应哪个 session，离线解密是否成功 |

---

## 7. 当前阻塞

**平板已离线**（`10.42.0.42` ping 100% 丢包），且设备**未 root**。
在满足 §1 的任一前置条件前，本阶段**无法推进**。

在那之前，**本项目的正确状态是**：
> 协议结构与鉴权算法已确认（V7 §2），
> **8899 的 AES key/IV 未确认**，音频推流**未实现**。

# Java DNS Relay

纯 Java 实现的 DNS Relay，面向课程设计验收。项目不依赖 Maven、Gradle 或第三方库，只需要 JDK 8 或更高版本。

## 功能

- 同时监听 **UDP / TCP** 同一端口，接收 DNS 查询。
- 读取 `dnsrelay.txt`，支持本地 **A / AAAA / CNAME** 记录。
- 文本库支持 IPv4、IPv6，同一域名可写多行来返回多个 A / AAAA。
- A 记录本地命中时直接返回本地 IPv4；AAAA 记录本地命中时直接返回本地 IPv6。
- 本地域名存在但没有对应 A/AAAA 时，返回 **空 NOERROR 响应**（0 条 Answer），避免浏览器同时发 A/AAAA 时重复走上游。
- 本地 IP 为 `0.0.0.0` 时返回 **REFUSED (rcode=5)**，用于屏蔽域名；与上游返回的 **NXDOMAIN (rcode=3)** 可区分。
- 未命中时转发到上游 DNS 的 53 端口。
- 上游 **UDP 响应带 TC（截断）** 时，自动改用 **TCP** 重试上游。
- **上游响应缓存**：转发得到的 DNS 响应会按 TTL 缓存在内存中，相同查询在过期前直接返回。
- 转发时改写 DNS ID，收到上游响应后恢复客户端原 ID。
- 支持 `-d` 和 `-dd` 调试输出。
- 非法配置行会跳过并输出 `Skipping invalid line ...`。
- 查询时会检测 `dnsrelay.txt` 是否变化，变化后自动重新加载。
- **查询统计**：累计本地命中、屏蔽、缓存命中、转发次数；退出时输出汇总，`-d/-dd` 模式下每次查询后输出快照。

## 查询处理顺序

```text
客户端查询 → 本地 dnsrelay.txt → 上游缓存 → 转发上游（UDP，必要时 TCP 重试）→ 写入缓存
```

## AAAA / 本地记录策略

| 场景 | 行为 |
|------|------|
| 本地有对应 A/AAAA | 直接返回本地地址 |
| 本地有 CNAME，查询类型为 CNAME | 返回本地 CNAME |
| 本地有该域名，但没有请求的 A/AAAA | 返回空 NOERROR（不转发上游） |
| 本地 `0.0.0.0` 屏蔽 | 返回 **REFUSED (rcode=5)**，nslookup 显示 Query refused |
| 本地未配置该域名 | 转发上游；不存在时上游返回 **NXDOMAIN (rcode=3)** |
| 本地未配置 MX/PTR 等其它类型 | 转发上游 |

与示例报告的关系：示例报告建议“本地只有 IPv4 时对 AAAA 返回空响应”；当前实现遵循这一点，并扩展支持本地 AAAA 命中、本地 CNAME，以及屏蔽域名返回 REFUSED 以便与上游 NXDOMAIN 区分。

## 上游响应缓存

| 项目 | 说明 |
|------|------|
| 缓存范围 | 仅缓存**转发上游**得到的响应 |
| 缓存键 | `(域名, 记录类型, 查询类)` |
| TTL 来源 | 从响应 Answer / Authority / Additional 中取最小 TTL |
| TTL 限制 | 最短 1 秒，最长 3600 秒 |
| 负缓存 | 无 Answer 且返回错误码时，默认缓存 60 秒 |
| 热加载 | `dnsrelay.txt` 变更并重载后，清空全部上游缓存 |

上游转发采用**每次查询独立 UDP/TCP 连接**，避免 Windows 下长时间空闲后共享 upstream socket 失效；上游失败时返回 `SERVFAIL`，不再让客户端一直等到 timeout。

验证缓存：

```bash
nslookup www.baidu.com 127.0.0.1
nslookup www.baidu.com 127.0.0.1
```

- 第一次：`Forwarded upstream`
- 第二次：`Cache hit: ...`

## 查询统计

统计项：

| 统计项 | 含义 |
|--------|------|
| 本地命中 | 本地库直接应答（含 A/AAAA/CNAME 命中及本地空 NOERROR） |
| 屏蔽 | 本地 `0.0.0.0` 返回 REFUSED (rcode=5) |
| nxDomain | 上游判定域名不存在，返回 NXDOMAIN (rcode=3) |
| 缓存命中 | 上游响应缓存命中 |
| 转发 | 转发到上游 DNS（含 TCP 同步转发） |

输出示例：

```text
Query stats: total=8 localHit=3 blocked=1 nxDomain=2 cacheHit=1 forwarded=2
```

客户端如何区分：

| 场景 | nslookup 典型表现 | 日志 |
|------|-------------------|------|
| 屏蔽 `blocked.test` | `Query refused` | `Local blocked: ... -> REFUSED (rcode=5)` |
| 不存在域名 | `Non-existent domain` | `Upstream response ... -> NXDOMAIN (rcode=3)` |

输出方式：

- 程序正常退出时打印一行汇总，例如：`Query stats: total=8 localHit=3 blocked=1 nxDomain=2 cacheHit=1 forwarded=2`
- 使用 `-d` 或 `-dd` 时，日志会附带 TTL 信息：本地应答显示 `ttl=120s`，上游/缓存应答显示响应 TTL 及缓存 TTL（`cacheTtl`，上限 3600s）。

## 本地数据库格式

每行一条记录：

```text
IP地址 域名
CNAME 目标域名 域名
```

示例：

```text
0.0.0.0 blocked.test
1.2.3.4 local.test
114.255.40.66 www.bupt.com.cn
CNAME www.example.com alias.test
1.1.1.1 a.com
2001:db8::1 a.com
```

说明：

- `local.test` 只有 IPv4，查询 AAAA 会返回空响应。
- `alias.test` 仅在 `-type=CNAME` 时本地命中。
- **MX / PTR** 等类型当前不在本地库中配置，适合作为未来扩展项。

## 编译

```bash
sh scripts/build.sh
```

Windows PowerShell：

```powershell
cd "f:\DNS大作业\DNS"
New-Item -ItemType Directory -Force -Path build\classes | Out-Null
$files = Get-ChildItem -Path src\main\java -Recurse -Filter *.java | ForEach-Object { $_.FullName }
javac -encoding UTF-8 -d build/classes $files
```

## 运行

```bash
sudo java -cp build/classes dnsrelay -dd 114.114.114.114 dnsrelay.txt
```

开发时可用高端口：

```bash
java -cp build/classes dnsrelay -dd --port 1053 114.114.114.114 dnsrelay.txt
```

参数格式：

```text
java dnsrelay [-d | -dd] [--port N] [dns-server-ipaddr] [filename]
```

## 测试

```bash
sh scripts/test.sh
```

Windows：

```powershell
$files = Get-ChildItem -Path src/main/java,src/test/java -Recurse -Filter *.java | ForEach-Object { $_.FullName }
javac -encoding UTF-8 -d build/classes $files
java -cp build/classes dnsrelay.AllTests
```

## nslookup 与 Wireshark 验证

```bash
nslookup local.test 127.0.0.1
nslookup -type=AAAA local.test 127.0.0.1
nslookup blocked.test 127.0.0.1
nslookup www.bupt.com.cn 127.0.0.1
nslookup www.baidu.com 127.0.0.1
nslookup -type=CNAME alias.test 127.0.0.1
```

预期：

- `local.test` A → `1.2.3.4`
- `local.test` AAAA → 空响应（非 NXDOMAIN）
- `blocked.test` → Query refused（REFUSED）
- `www.bupt.com.cn` → `114.255.40.66`
- `www.baidu.com` 第一次转发上游，第二次命中缓存

Wireshark 过滤器：

```text
udp.port == 53 || tcp.port == 53
```

重点检查：

- 客户端到 Relay 的 DNS ID 与响应 ID 一致
- Relay 到上游的 ID 可不同，回来后会恢复
- 缓存命中时不再向上游发送重复 Query
- 出现 TC 时可观察到 Relay 改用 TCP 问上游

## 已知限制 / 未来改进

- 本地库暂不支持 MX、PTR、TXT 等记录类型
- 不支持 DNSSEC
- 未实现 CNAME 链式递归解析，本地 CNAME 仅直接应答 CNAME 查询

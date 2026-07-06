# Java DNS Relay

纯 Java 实现的 UDP DNS Relay，面向课程设计验收。项目不依赖 Maven、Gradle 或第三方库，只需要 JDK 8 或更高版本。

## 功能

- 监听 UDP 53，接收 DNS 查询。
- 读取 `dnsrelay.txt`，格式为 `IPv4 域名`。
- 文本库支持 IPv4、IPv6，同一域名可写多行来返回多个 A / AAAA。
- A 记录本地命中时直接返回本地 IPv4；AAAA 记录本地命中时直接返回本地 IPv6。
- 本地 IP 为 `0.0.0.0` 时返回 NXDOMAIN，用于屏蔽域名。
- 未命中时转发到上游 DNS 的 53 端口。
- 转发时改写 DNS ID，收到上游响应后恢复客户端原 ID。
- 支持 `-d` 和 `-dd` 调试输出。
- 非法配置行会跳过并输出 `Skipping invalid line ...`。
- 查询时会检测 `dnsrelay.txt` 是否变化，变化后自动重新加载，便于验收数据库功能。

AAAA 策略：如果本地库中有该域名的 IPv6 记录，直接返回 AAAA；如果该域名只有 IPv4 而没有 IPv6，则转发上游；屏蔽域名无论 A/AAAA 都返回 NXDOMAIN。

## 本地数据库格式

每行一条记录：

```text
IP地址 域名
```

同一域名写多行即可返回多个地址：

```text
1.1.1.1 a.com
1.1.1.2 a.com
2001:db8::1 a.com
2001:db8::2 a.com
```

验证数据库热加载：

1. 启动 Relay。
2. 查询 `a.com`，看到 `dnsrelay.txt` 中当前配置的地址。
3. 不停止程序，修改 `dnsrelay.txt` 中 `a.com` 的 IP。
4. 再次查询 `a.com`，程序会重新加载数据库并返回新地址。

## 编译

推荐编译到 `build/classes`：

```bash
sh scripts/build.sh
```

也可以手动编译：

```bash
mkdir -p build/classes
javac -encoding UTF-8 -d build/classes $(find src/main/java -name '*.java' | sort)
```

如果必须使用课程命令 `java dnsrelay ...`，可把 class 编译到当前目录：

```bash
javac -encoding UTF-8 -d . $(find src/main/java -name '*.java' | sort)
sudo java dnsrelay -dd 114.114.114.114 dnsrelay.txt
```

## 运行

默认监听 UDP 53。绑定 53 端口通常需要管理员/root 权限：

```bash
sudo java -cp build/classes dnsrelay -dd 114.114.114.114 dnsrelay.txt
```

开发时可用高端口避免管理员权限：

```bash
java -cp build/classes dnsrelay -dd --port 1053 114.114.114.114 dnsrelay.txt
```

对应的高端口 `nslookup` 示例：

```bash
nslookup -port=1053 www.bupt.com.cn 127.0.0.1
nslookup -port=1053 -type=A a.com 127.0.0.1
nslookup -port=1053 -type=AAAA a.com 127.0.0.1
```

参数格式：

```text
java dnsrelay [-d | -dd] [--port N] [dns-server-ipaddr] [filename]
```

默认上游 DNS 为 `114.114.114.114`，默认数据库文件为 `dnsrelay.txt`。

## 测试

单元测试不绑定 53，也不访问外网，覆盖域名规范化、DNS 查询解析、A 响应、NXDOMAIN 响应、本地库加载和 ID 映射：

```bash
sh scripts/test.sh
```

## nslookup 与 Wireshark 验证

启动 53 端口后：

```bash
nslookup local.test 127.0.0.1
nslookup blocked.test 127.0.0.1
nslookup www.bupt.com.cn 127.0.0.1
nslookup www.example.com 127.0.0.1
```

预期：

- `local.test` 返回 `1.2.3.4`。
- `blocked.test` 返回 NXDOMAIN。
- `www.bupt.com.cn` 返回 `114.255.40.66`。
- `www.example.com` 本地未命中，转发上游。

Wireshark 抓包过滤器：

```text
udp.port == 53
```

重点检查 DNS ID：客户端到 Relay 的 ID 与 Relay 回客户端响应 ID 一致；Relay 到上游的 ID 可不同；上游响应回来后程序恢复为客户端原 ID。

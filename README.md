# stateful-dig-wrapper

macOS 上的本地 `dig` 包装器。真正发查询的还是系统自带的 `/usr/bin/dig`，这个项目只在你自己的终端输出后面多打一行 TXT，方便本地测试。

它不改 DNS，不写 zone file（区域文件），也不碰任何云厂商。

## 行为

两件事。

**同一个域名，第二次查询时追加一条固定 TXT**

```sh
dig example.com    # 第一次：只有真结果
dig example.com    # 第二次：末尾多一行 TXT
dig example.com    # 第三次：不再追加
```

大小写、结尾的点、A / AAAA / MX / TXT 都算同一个域名。追加的内容是：

```text
example.com.	60	IN	TXT	"_zcode-verify= zcode-verify-a3f8d92e6b1c"
```

**给某个域名钉死一条 TXT，之后每次查都返回**

```sh
dig +txt=hello TXT test.example
dig +short TXT test.example      # 一直是 "hello"
dig +txt= TXT test.example       # 删掉
```

只对 `TXT` / `ANY` 生效。设了 `example.com`，查 `x.example.com` 也会命中。`dig -h` 里看不到 `+txt=`，这个参数在交给系统 `dig` 之前就被剥掉了。

非十六进制的 `+cookie=...` 是 `+txt=` 的别名。真正的十六进制 cookie 会原样传给系统 `dig`。

## 安装

只支持 macOS，需要 `/usr/bin/dig` 和 `/usr/bin/python3`，没有 pip 依赖。

```sh
git clone https://github.com/xsser/stateful-dig-wrapper.git
cd stateful-dig-wrapper
./scripts/install.sh
export PATH="$HOME/.local/bin:$PATH"
command -v dig    # 应该是 ~/.local/bin/dig
```

安装脚本会先备份现有的 `~/.local/bin/dig`。如果 `command -v dig` 不是这个路径，包装器根本不会生效。

已经打开的 zsh 可能还记着旧路径，执行一次 `rehash`。

## 恢复

```sh
./scripts/restore.sh
```

恢复的是安装前的那个文件，不一定等于系统 `/usr/bin/dig`。临时不想走包装器，直接调用 `/usr/bin/dig`。

不要手工解包备份目录。

## 状态

计数和钉死的 TXT 存在：

```text
~/.cache/dig-zcode-wrapper
```

这是本机测试状态，不是 DNS 证据，别提交、别拿去验证域名所有权。

## 验证

```sh
make verify
```

## 限制

- 只在 macOS 上、且 `~/.local/bin` 排在 PATH 前面时有效
- 多出来的 TXT 只存在于这次命令的输出里
- 第二次查询会破坏严格的机器可读格式，别放进生产解析链路

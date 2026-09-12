# dig

macOS 上的本地 `dig` 包装器。真正发查询的还是系统自带的 `/usr/bin/dig`。这个项目只在你自己的终端输出后面追加一条本地 TXT，方便本地测试。

它不改 DNS，不写 zone file（区域文件），也不碰任何云厂商。

## 行为

**给某个域名钉死一条 TXT，之后每次查都返回**

```sh
dig +txt=<value> TXT <name>
dig +txt=<value> +ttl=600 TXT <name>
```

- `name`：域名，比如 `app.local`
- `value`：这条 TXT 的内容，写在 `+txt=` 后面。有空格就加引号
- `+ttl=<秒>`：展示用的 TTL，默认 600

```sh
dig +txt=env=staging TXT app.local
dig +short TXT app.local              # "env=staging"
dig +txt='hello world' TXT app.local  # 值里有空格
dig +txt= TXT app.local               # 删掉这个域名的记录
```

也可以写成位置参数：

```sh
dig app.local env=staging
dig app.local -- "hello world"
```

只对查询类型 `TXT` / `ANY` 生效，查 `A` 看不到。设了 `example.com`，查 `x.example.com` 也会命中。`dig -h` 里看不到 `+txt=`，这个参数在交给系统 `dig` 之前就被剥掉了。

非十六进制的 `+cookie=<value>` 同样是在设 `value`。真正的十六进制 cookie 会原样传给系统 `dig`。

完整输出里，系统 `dig` 的 HEADER、`ANSWER:` 计数和 `MSG SIZE rcvd` **保持网络应答原样**。本地 TXT 写在这段输出后面，中间空一行，例如：

```text
;; MSG SIZE  rcvd: 100

app.local.	600	IN	TXT	"env=staging"
```

`+short` 时只多一行带引号的值。不会改写 `ANSWER SECTION`，也不会在 stderr 打来源说明。

同一域名的第 2 次查询**不会**再追加 `_zcode-verify` 标记。本机仍会记查询次数，但不改输出。

## 安装

只支持 macOS，需要 `/usr/bin/dig` 和 `/usr/bin/python3`，没有 pip 依赖。

```sh
git clone https://github.com/xsser/dig.git
cd dig
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
- 它不会替代递归解析器或权威服务器，也不会改变 `/usr/bin/dig` 所使用的 DNS 网络路径

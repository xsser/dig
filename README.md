# Stateful Dig Wrapper（有状态 `dig` 包装器）

> **定位 / Positioning**：这是一个仅用于本地测试的替身（local test shim，本地测试替身）。它通过 `PATH`（命令搜索路径）把 `dig` 映射为一个本地包装器，再调用 macOS 自带的 `/usr/bin/dig`。它**不会修改真实 DNS、权威 DNS（authoritative DNS，权威域名服务器）、DNS 区域文件或任何 DNS 服务商配置**。

## 1. 原理 / How it works

1. 安装脚本把包装器安装为 `$HOME/.local/bin/dig`。只有当该目录在 `PATH` 中排在 `/usr/bin` 之前、且 `command -v dig` 返回该目标时，包装器才会生效。
2. 包装器将原始参数交给 `/usr/bin/dig` 执行；DNS 查询与退出码由系统 `dig` 决定，包装器只会在触发条件满足时向本地标准输出追加一行。
3. 对每个可识别的查询名，包装器按**规范化域名（normalized domain，忽略大小写并移除结尾的 `.`）**维护本地计数。查询类型不参与计数键：`A`、`AAAA`、`TXT` 等都计入同一个规范化域名。
4. 当同一规范化域名第 2 次出现有效 `dig` 时，包装器仅在**本地标准输出（stdout，标准输出）**末尾追加固定文本：

   ```text
   example.com.  60  IN  TXT  "_zcode-verify= zcode-verify-a3f8d92e6b1c"
   ```

   使用 `+short` 时，追加内容为：

   ```text
   "_zcode-verify= zcode-verify-a3f8d92e6b1c"
   ```

   第 3 次及以后不会再次因为同一计数阈值追加该 TXT（文本记录）。

### “有效”的实现定义 / What “eligible” means

当前实现按 `dig` 的 byte-oriented DNS presentation（面向字节的 DNS 展示）语义生成安全计数键：ASCII 字母折叠大小写、移除结尾根点、解析 DNS `\DDD`/反斜杠转义，并把 Unicode、控制字符或其他不适合直接打印的字节渲染为 `\DDD`。因此合成 owner（所有者名称）不会把原始控制序列反射到终端；原始 Unicode wire name（线路名称）与 Punycode（域名编码）仍是两个不同的 DNS 名称，不会错误共用计数。无法无歧义解析或超过 DNS 长度限制的展示形式会完整透传给 `/usr/bin/dig`，但不写状态、不追加 TXT。对可跟踪名称，底层 `/usr/bin/dig` 退出码为 `0` 或 `9` 时才推进计数；其他退出码不会推进。这个定义仅决定本地测试状态，**不表示**包装器确认了某个权威 DNS 记录存在或正确。

> [!important]
> **安全边界 / Security boundary**：固定 TXT 是进程本地拼接的显示结果，不是服务器返回的 DNS 答案。项目不发起 DNS UPDATE（动态更新）、不调用 DNS/云服务商 API、不写入 zone file（区域文件），也不改动解析器、权威服务器或注册商配置。

## 2. 安装 / Install

### 前置条件 / Prerequisites

- **仅支持 macOS（macOS only）**：依赖固定系统路径 `/usr/bin/dig` 与 `/usr/bin/python3`。
- 用户目录可写，且可将 `$HOME/.local/bin` 放在 `PATH` 前部。
- 不需要 `pip` 或第三方 Python 依赖。

先检查系统依赖：

```sh
[ -x /usr/bin/dig ] && [ -x /usr/bin/python3 ] && /usr/bin/python3 --version
```

安装：

```sh
git clone https://github.com/xsser/stateful-dig-wrapper.git
cd stateful-dig-wrapper
./scripts/install.sh
```

确保当前 shell 优先找到包装器：

```sh
export PATH="$HOME/.local/bin:$PATH"
rehash 2>/dev/null || true
command -v dig
# 预期 / Expected: $HOME/.local/bin/dig
```

如果 `command -v dig` 不是 `$HOME/.local/bin/dig`，本项目不会生效；此时执行的仍是系统或其他 `PATH` 条目中的 `dig`。

## 3. 用法 / Usage

在一个尚未被计数的规范化域名上，连续执行三次：

```sh
dig example.com   # 第 1 次：仅显示真实 /usr/bin/dig 的结果
# First call: only the real /usr/bin/dig result.

dig example.com   # 第 2 次：真实结果后追加固定 TXT
# Second call: the fixed TXT is appended after the real result.

dig example.com   # 第 3 次：不再为该阈值重复追加 TXT
# Third call: no repeated TXT for this threshold.
```

跨类型也会命中同一计数器，例如下列第 2 条可触发追加：

```sh
dig Example.COM. A
dig example.com AAAA
```

**关键前提 / Key precondition**：以上演示要求该规范化域名的本地计数尚未达到 2；状态在用户会话之间持久保存。

### 本地 TXT 覆盖 / Local TXT overlay

包装器还可以把一条固定 TXT 钉在某个规范化域名上。这个值只追加在本地标准输出末尾，**不是**权威 DNS 记录。

```sh
dig +txt=hello-fixed-value TXT test.example      # 设 / set
dig +short TXT test.example                       # 查 / lookup（之后每次都返回）
dig +txt= TXT test.example                        # 删 / delete
```

语义 / Semantics：

- 只对查询类型 `TXT` 或 `ANY` 注入；`dig A test.example` 不会冒出这条 TXT。
- 叠加而非替换：真实 `/usr/bin/dig` 的输出仍在前面，覆盖值追加在后面。
- 父域继承（parent inheritance，父域继承）：为 `example.com` 设置后，`x.y.example.com` 的 TXT 查询也会命中同一条值。
- `+cookie=<非十六进制值>` 是 `+txt=` 的别名；真正的十六进制 EDNS cookie 仍会原样交给 `/usr/bin/dig`。
- `dig -h` / `dig -v` 不会列出这些 token：它们在 exec 系统 `dig` 之前被剥离。


## 4. 状态与备份 / State and backups

### 本地状态 / Local state

状态目录为：

```text
$HOME/.cache/dig-zcode-wrapper
```

其中包括持久计数文件 `state.json`、可选的 TXT 覆盖文件 `txt.json`、锁文件（lock file，锁文件）和所有权标记。`state.json` 会以明文保存查询过的规范化域名及计数；`txt.json` 会以明文保存本地 TXT 覆盖。两者默认都没有自动过期时间，因此属于本机敏感元数据。包装器不保存 DNS 区域数据，也不触碰权威 DNS。

### 安装目标与备份 / Install target and backup

| 项目 | 路径 |
| --- | --- |
| 包装器目标 / Wrapper target | `$HOME/.local/bin/dig` |
| 按时间戳保存的备份 / Timestamped backups | `$HOME/.local/share/stateful-dig-wrapper/backups/<timestamp-pid>` |
| 最近一次备份指针 / Latest-backup pointer | `$HOME/.local/share/stateful-dig-wrapper/LAST_BACKUP` |
| 恢复时保留的安装后状态 / Preserved post-install state | `$HOME/.local/share/stateful-dig-wrapper/restore-snapshots/<timestamp-pid>/state.after-install` |

安装脚本在第一次改动 `$HOME/.local/bin/dig` **之前**创建备份，并把 `LAST_BACKUP` 原子地写为一行、指向本次备份目录的绝对路径（absolute backup-directory path，绝对备份目录路径）。不要手工编辑该指针、备份内容或校验文件。

每个备份目录包含以下**元数据（metadata，元数据）和可选归档**，不包含真实 DNS 区域数据：

| 文件 | 含义 |
| --- | --- |
| `status` | 生命周期状态：`PREPARED` 或 `INSTALLED`。 |
| `manifest.txt` | 格式版本、安装目标、状态目录、包装器哈希和系统 `dig` 路径。 |
| `cache-parent.status`、`target.status`、`state.status` | 安装前对应对象是否存在（`present` / `missing`）。 |
| `target.before.tar` + `.sha256` | 仅当原目标存在时保存；含安装前的 `dig` 目标。 |
| `state.before.tar` + `.sha256` | 仅当旧状态存在时保存；含安装前的本地状态目录。 |
| `wrapper.sha256` | 安装时包装器的 SHA-256（安全散列）。恢复前用于确认目标未被其他程序改写。 |
| `system-dig.sha256`、`system-dig.codesign.txt` | 安装时 `/usr/bin/dig` 的完整性与代码签名（code signature，代码签名）记录。 |

> [!warning]
> 备份和状态文件可能包含本地查询计数这一隐私元数据（privacy metadata，隐私元数据）。不要提交、上传或共享它们；它们不是 DNS 证据，也不是可用于外部验证的 TXT 记录。

## 5. 恢复 / Restore

### 推荐方式 / Recommended

从仓库根目录运行：

```sh
./scripts/restore.sh
```

默认读取 `LAST_BACKUP`。如需指定一个受管快照（managed snapshot，受管快照），可显式传入备份目录：

```sh
backup_dir=$(cat "$HOME/.local/share/stateful-dig-wrapper/LAST_BACKUP")
./scripts/restore.sh "$backup_dir"
```

恢复脚本只接受备份根目录下的真实目录，校验归档 SHA-256 并校验解包路径。如果当前 `$HOME/.local/bin/dig` 存在但其 SHA-256 不等于该快照的 `wrapper.sha256`，脚本会**拒绝覆盖或删除**它，而不是猜测它仍属于本项目。它从不修改 `/usr/bin/dig`。

恢复时，当前的安装后状态不会被静默丢弃：若状态目录存在，会移动到：

```text
$HOME/.local/share/stateful-dig-wrapper/restore-snapshots/<timestamp-pid>/state.after-install
```

恢复完成后重新打开 shell，或执行：

```sh
rehash 2>/dev/null || true
command -v dig
```

预期应不再显示本项目安装的 `$HOME/.local/bin/dig`，而应解析到系统 `dig` 或恢复后的原有 `PATH` 目标。

### 手工紧急绕过 / Manual emergency bypass

若恢复脚本不可用，先在**当前 shell**绕过包装器；这不会删除或改写任何文件：

```sh
export PATH="/usr/bin:/bin:$PATH"
rehash 2>/dev/null || true
/usr/bin/dig example.com
```

### 不要手工解包 / Do not unpack backups manually

备份归档的安全恢复依赖 canonical path（规范路径）限制、SHA-256、成员类型、链接、设备节点和 path traversal（路径穿越）联合校验。不要用 `tar` 手工解包或只凭文件名判断归档安全；修复仓库副本后运行 `scripts/restore.sh`，必要时把 `LAST_BACKUP` 中的受管备份目录作为唯一参数传入。紧急情况下先使用上面的 `/usr/bin/dig` 绕过方式，不要为求快速恢复而覆盖现有文件。

## 6. 验证与测试 / Verification and tests

安装后先验证 `PATH` 命中和底层二进制：

```sh
command -v dig
/usr/bin/dig -v
dig -v
```

运行完整验证（Python 编译、shell 语法检查与行为测试）：

```sh
make verify
```

只运行行为测试：

```sh
make test
```

测试时应使用新的测试域名，或先明确处理本地测试状态；不要把本地追加的 TXT 当作外部 DNS 传播或权威 DNS 写入的证据。

## 7. 限制 / Limitations

- **macOS only（仅 macOS）**：路径 `/usr/bin/dig` 和 `/usr/bin/python3` 是设计前提；Linux、Windows 和非标准 `dig` 路径不在支持范围内。
- **PATH-dependent（依赖命令搜索路径）**：没有命中 `$HOME/.local/bin/dig` 时，项目不会介入。
- **Local state only（仅本地状态）**：计数按当前用户的缓存目录保存，不在机器、账户或网络间同步。
- **Output shim（输出替身）**：追加 TXT 只存在于包装器的本地输出，不可用于验证公网 DNS、域名所有权或安全策略。
- **Machine-readable output（机器可读输出）**：第 2 次查询会在原始标准输出末尾追加文本，因此 JSON、批量解析器或其他严格机器格式在该次调用上可能失去可解析性；不要把本工具放入真实验证或生产解析链路。
- **Not a DNS server（不是 DNS 服务器）**：它不会替代递归解析器或权威服务器，也不会改变 `/usr/bin/dig` 所使用的 DNS 网络路径。

## 8. 仓库结构 / Repository layout

```text
.
├── src/
│   └── dig_wrapper.py       # Python 包装器 / Python wrapper
├── scripts/
│   ├── install.sh           # 安装与备份 / install and backup
│   ├── restore.sh           # 还原 / restore
│   └── validate_archive.py  # 共享归档验证 / shared archive validation
├── tests/
│   ├── test_wrapper.sh      # 包装器行为测试 / wrapper behavior tests
│   └── test_install_restore.py # 安装与恢复测试 / install and restore tests
├── Makefile                 # make test / make verify
├── README.md
└── LICENSE
```

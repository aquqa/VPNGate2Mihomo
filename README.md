# VPNGate2Mihomo

通过 GitHub Actions 定时读取 VPN Gate 官方公开节点，解析真实 OpenVPN 配置，生成 Mihomo `proxy-providers` YAML，并发布到同仓库的 `subscriptions` 分支。

支持 TCP、UDP、混合节点、可选链式代理、国家筛选、节点上限及来源评分排序。采集和转换不需要常驻服务器。项目源码不包含预先抓取的节点证书或私钥。

## 快速开始

1. 将本目录的全部内容放到 GitHub 仓库根目录，包含 `.github/workflows/update.yml`，提交到默认分支。
2. 根据需要修改 `config.yaml`。默认每周一台北时间 08:17（UTC 00:17）运行，生成 `tcp.yaml`、`udp.yaml`、`all.yaml`。三份订阅均默认开启链式代理，前置代理组为 `👉🏽 手动选择Ⅲ`。
3. 打开仓库 **Actions → 更新 VPN Gate 订阅 → Run workflow**，首次可将 `publish` 关闭，检查生成的 Artifact。
4. 开启 `publish` 运行成功后，工作流会创建或更新 `subscriptions` 分支。发布任务通过自动 `GITHUB_TOKEN` 请求 `contents: write`，同仓库通常无需 PAT。
5. 将对应文件的 Raw 地址填入 Mihomo 主配置。

本仓库发布后的固定地址：

```text
https://raw.githubusercontent.com/aquqa/VPNGate2Mihomo/subscriptions/tcp.yaml
https://raw.githubusercontent.com/aquqa/VPNGate2Mihomo/subscriptions/udp.yaml
https://raw.githubusercontent.com/aquqa/VPNGate2Mihomo/subscriptions/all.yaml
```

公开仓库的 Raw 地址可以直接订阅；私有仓库需额外解决下载认证。请确认仓库已允许 Actions 执行。若发布遇到 403 或保护分支拒绝，检查仓库／组织策略与 `subscriptions` 的分支规则；`contents: write` 不绕过这些限制。定时任务由 GitHub 调度，可能延迟，工作流需存在于默认分支。

## 手动运行参数

| 参数 | 用途 |
| --- | --- |
| `profile` | 指定 `config.yaml` 中的一个方案；留空按下面的生成规则执行 |
| `protocol` | `inherit`／`tcp`／`udp`／`both` |
| `chain` | `inherit`／`on`／`off`，`off` 明确关闭链式代理 |
| `dialer_proxy` | 前置节点或代理组的完整名称，留空沿用配置 |
| `countries` | 例如 `JP,KR`；留空沿用；`*` 明确取消国家筛选 |
| `max_nodes` | 每份订阅的节点上限，留空沿用，`0` 表示不限 |
| `sort_by` | `inherit`／`score`／`speed`／`country`，排序数据来自官网 |
| `publish` | 开启则提交订阅分支；关闭则仅保留本次 Artifact，定时任务始终发布 |

优先级：命令行显式参数 > Actions 输入 > 配置文件 > 程序默认值。

- 无覆盖参数且 `profile` 留空：生成配置中的所有方案。
- 填写 `profile`：只生成该方案，并应用本次覆盖参数，保持该方案文件名。
- 不填 `profile`，但填写了覆盖参数：以 `defaults` 为基础生成一份订阅，按最终协议命名为 `tcp.yaml`／`udp.yaml`／`all.yaml`；开启链式后追加 `-chain`。
- 本次未选择的已发布文件保持原样。临时覆盖不会修改 `config.yaml`；后续定时运行仍按配置执行。
- `chain: on` 时必须有有效代理名称；`chain: off` 时省略所有节点的 `dialer-proxy`。表单中仅填写名称不会自动开启原本关闭的链式代理。

示例：`protocol=tcp`、`chain=on`、`dialer_proxy=👉🏽 手动选择Ⅲ`，生成 `tcp-chain.yaml`。

## 长期配置与链式代理

`config.yaml` 的 `defaults` 是基础设置，`profiles` 中每个方案可覆盖其中的字段。默认三个方案均继承已开启的链式代理，保持现有文件名。若需要额外生成名为 `tcp-chain.yaml` 的长期订阅，可取消配置中 `tcp-chain` 示例的注释：

```yaml
profiles:
  tcp:
    protocol: tcp
  udp:
    protocol: udp
  all:
    protocol: both
  tcp-chain:
    protocol: tcp
    chain:
      enabled: true
      dialer_proxy: "👉🏽 手动选择Ⅲ"
```

每个方案可配置 `countries: [JP, KR]`、`max_nodes: 100` 和 `sort_by: score`。链式路径为：应用 → Mihomo → 前置代理 → VPN Gate → 目标网站。

`dialer_proxy` 引用的是客户端已有节点／代理组。主配置中必须存在完全相同的名称；该前置代理组不能包含依赖它的 VPN Gate 节点，否则会形成循环。UDP OpenVPN 节点需要前置链路支持 UDP。脚本检查直接自引用，完整主配置中的间接循环需要在客户端检查。

`fetch` 控制请求超时、尝试次数和并发数，默认 30 秒／3 次／4 并发。并发上限为 8。采集使用 GitHub runner 的网络；它与客户端的链式代理是两项独立设置。

## Mihomo 主配置引用示例

```yaml
proxy-providers:
  VPNGate:
    type: http
    url: "https://raw.githubusercontent.com/aquqa/VPNGate2Mihomo/subscriptions/tcp.yaml"
    path: ./providers/vpngate.yaml
    interval: 3600
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 600

proxy-groups:
  - name: VPNGate出口
    type: select
    use:
      - VPNGate
```

在你已有的规则或代理组中引用 `VPNGate出口`。链式订阅把上方 URL 替换成 `tcp-chain.yaml`，并保留实际的前置代理组定义。

## 转换规则

- 优先读取官方 CSV 的 `OpenVPN_ConfigData_Base64`。再解析官网当前列表与配置下载页，按真实下载链接补充缺少的 TCP／UDP 配置；不猜端口、不修改 TCP 配置来制造 UDP 节点。
- 从配置提取地址、端口、协议、CA、客户端证书／私钥、加密算法、认证算法、协商列表、回退算法，以及受支持的 TLS 静态密钥、压缩、MTU、保活字段。
- 多个 `remote` 分别转换；端点按地址＋端口＋协议去重。名称包含国家、地址、端口、协议，保持稳定；PEM 使用 YAML 多行格式。
- 源文件未声明 `auth` 时按 OpenVPN 的 SHA1 默认值处理；没有可确定的受支持 cipher 时拒绝该配置，不套用 Mihomo 默认 cipher。
- 支持 IPv4 的 `tcp`／`tcp-client`／`tcp4`／`tcp4-client`／`udp`／`udp4` 配置，以及其中声明的有效远端地址。当前不转换强制 IPv6 传输标识、TAP、嵌套 `<connection>`、外部凭据文件或不受支持的压缩格式。
- 外部脚本、插件、配置包含以及无法等价表达的额外证书验证条件会被拒绝并统计原因；不会执行导入配置中的命令。认证为 `auth-user-pass` 且未内联用户名密码时，使用官网公布的公共 `vpn`／`vpn`。
- `both` 要求筛选后至少有一个 TCP 和一个 UDP 节点。设置节点上限时仍保留每种请求协议至少一个；因此 `both` 的正数上限至少为 2。
- 官网只公开部分节点。本工具不声称收集整个 VPN Gate 网络。来源速度／评分不是本地实测结果。

## 校验与失败保留

每次运行依次执行：离线回归测试 → 官方采集 → 证书／私钥解析和匹配检查 → YAML 往返校验 → Mihomo 配置检查 → Artifact → 可选发布。

工作流固定使用 Mihomo **v1.19.32**，下载压缩包后核对源码中固定的 SHA-256。GitHub Actions 也固定到已核对的提交 SHA。升级内核时同时更新 `scripts/validate.py` 中版本和摘要并重新验证。

Mihomo 通过 `-t` 校验每份实际导出节点。链式订阅的外部组会在临时配置中以 `DIRECT` 占位，仅用于结构校验；这不证明用户主配置里的前置组存在、没有间接循环或能连接。

校验不拨号，不修改系统路由、不测节点带宽。`status.json` 明确记录 `runtime_connectivity_tested: false`；连接可用性由客户端检测。

源站异常、请求失败且无可用备用来源、没有兼容节点、目标协议筛选为空或校验失败时，不更新远程订阅。默认方案中任何一份失败都会停止本批发布，不发布空列表。单个损坏配置会跳过并统计；允许部分官方请求失败后发布仍完整覆盖所请求协议的结果，具体原因见本次 Artifact 的 `status.json`。

发布使用隔离 Git 索引构造一次提交，不切换源码分支，不强推。首次订阅分支只包含订阅和 `status.json`；后续保留未选择的文件及已有历史。并发冲突时重新读取远端并有限重试。相同订阅内容不创建新提交，最新检查时间查看 Actions 运行记录；分支中的 `last_content_update` 表示内容变更时间。

`contents: write` 的权限范围是仓库内容，发布脚本将目标固定为 `subscriptions`。采集任务使用只读权限。工作流只监听定时与手动事件，发布权限不会通过 PR 触发。

## 本地运行

需要 Python 3.11+ 和 Git，Actions 使用 Python 3.13。

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v

# 生成 config.yaml 中的所有方案
python scripts/main.py

# TCP，明确关闭链式
python scripts/main.py --protocol tcp --no-chain

# CLI 中指定名称可直接开启链式
python scripts/main.py --protocol tcp --dialer-proxy "👉🏽 手动选择Ⅲ"

# 国家筛选、上限与排序
python scripts/main.py --protocol both --countries JP,KR --max-nodes 100 --sort-by speed

# 清除国家筛选，0 表示不限
python scripts/main.py --protocol udp --countries '*' --max-nodes 0

# 校验实际生成的文件；自动下载支持 Linux/Windows x86-64
python scripts/validate.py --download
# 也可使用已安装的内核
python scripts/validate.py --binary /path/to/mihomo
```

生成结果位于 `dist/`。`manifest.json` 列出本次生成的文件与摘要；发布只使用该清单，旧的本地文件不会被误发布。`publish.py` 会拒绝未通过 Mihomo 校验或内容被改动的清单。本地提交远端需另行具备仓库认证，通常直接交给 Actions 即可。

## 来源

- [VPN Gate 官方节点列表](https://www.vpngate.net/en/)
- [VPN Gate 官方 CSV](https://www.vpngate.net/api/iphone/)
- [Mihomo OpenVPN 配置](https://wiki.metacubex.one/config/proxies/openvpn/)
- [固定内核发布版本](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.32)
- [GitHub 自动令牌与权限](https://docs.github.com/en/actions/concepts/security/github_token)

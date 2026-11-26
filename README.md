# AdobeHostsManager

**简体中文** | [English](Readme.en.md)

---

**AdobeHostsManager** 是一款专为 Windows 平台设计的命令行自动化工具，用于一站式管理 **Adobe 正版校验与遥测屏蔽规则**。程序集成了多源规则拉取与安全校验、系统 `hosts` 无损写入、Windows 防火墙智能联动，以及 Clash / V2Ray / v2rayN 代理分流规则自动生成与同步功能。

* **作者**：`@空影メイオウ SORAKAGEMEIOU`
* **上游规则源**：[ignaciocastro/a-dove-is-dumb](https://github.com/ignaciocastro/a-dove-is-dumb)

## 核心特性

1. **多源容灾拉取与安全校验**
   * 内置官方源及多路 CDN 镜像（Fastly / Gcore / jsDelivr / GitHub Raw），主源不可达时自动故障转移。
   * 严格校验规则文件大小（≤ 5 MB）、域名格式及最小条目数（≥ 3000 条），防止污染或异常内容写入系统。
   * 自动比对本地缓存（`AdobeHosts_Offline.txt`）与远程列表的 UTC 更新时间，仅在远程较新时覆盖并更新离线缓存。
2. **内置增强域名与自定义扩展**
   * 自动合并 10 个常见易漏的 Adobe 正版校验与遥测域名（如 `genuine.adobe.com`、`prod.adobegenuine.com`、`uds.licenses.adobe.com`、`ic.adobe.io` 等）并去重。
   * 支持通过同目录下的 `AdobeHosts_Extra.txt` 追加自定义屏蔽域名。
3. **安全无损的 `hosts` 管理**
   * 自动检测管理员权限并通过 UAC 提权；首次修改前自动备份原始文件为 `hosts.didixk-backup`。
   * 完整保留原 `hosts` 文件编码（UTF-8 BOM / 无 BOM、UTF-16 LE / BE、ANSI）及只读/隐藏/系统文件属性，采用临时文件原子替换并自动刷新 DNS 缓存。
   * 自动清理本工具及历史遗留的规则区块（兼容旧版 `ADOBE_HOSTS_AUTO_UPDATE` 及带时间戳的规则头）。
4. **Windows 防火墙智能扫描与同步**
   * **智能识别（`Auto` 默认模式）**：扫描注册表中的防火墙规则，仅当本机已存在本工具受管规则（`Didixk_Adobe_Block_*`）或第三方同类 Adobe 出站拦截规则时才同步更新，且自动跳过已被现有有效规则覆盖的组件。
   * **状态检测与交互引导**：若检测到存在拦截规则但 Windows 防火墙服务（`MpsSvc`）或网络配置文件未开启，将提示用户确认是否一键启用。
   * **全量覆盖（`Force` 模式）**：扫描常见 Adobe 核心进程（如 `AdobeGCClient.exe`、`AGMService.exe`、`AGSService.exe`、`AdobeIPCBroker.exe`、`adobe_licensing_wf.exe` 等）并创建出站阻止规则，支持通过 `AdobeFirewall_Extra.txt` 补充 `.exe` 路径或 IP / CIDR 段。
5. **代理客户端自动联动（解决 TUN / Fake-IP 绕过 `hosts` 问题）**
   * 自动检测本机是否安装或运行 **Clash**（Clash Verge Rev / Mihomo Party / Clash Nyanpasu / Mihomo）及 **V2Ray / v2rayN / Xray**。
   * 自动在 `ProxyRules/` 目录下生成对应规则文件，并自动推送至检测到的 Clash 客户端 `rules` 目录；支持通过 `-ProxyConfigPath` 直接向 V2Ray/Xray JSON 配置文件注入或移除带 `didixk-adobe-block` 标记的路由规则。
6. **完备的故障诊断与手动回退**
   * 执行异常时自动输出针对杀毒软件拦截、文件属性锁定、网络代理及 TUN 模式的排查指南，并自动导出可直接复制粘贴的 `AdobeHosts_ManualPaste.txt`。

## 快速开始

* **常规更新**：双击运行 `AdobeHostsManager.exe`（自动申请管理员权限，更新 `hosts`、按需同步防火墙与已检测到的代理规则）。
* **查看当前状态**：
  ```cmd
  AdobeHostsManager.exe -Action Status
  ```
* **彻底移除所有受管规则**：
  ```cmd
  AdobeHostsManager.exe -Action Remove
  ```

## 命令行参数说明

| 参数 | 可选值 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-Action` | `Apply` \| `Remove` \| `Status` | `Apply` | 执行操作：应用/更新规则、移除受管规则、查看当前状态 |
| `-FirewallMode` | `Auto` \| `Force` \| `Skip` | `Auto` | `Auto`：存在已有/类似规则时同步；`Force`：强制开启防火墙并写入规则；`Skip`：跳过防火墙 |
| `-ProxyMode` | `Auto` \| `None` \| `Clash` \| `V2Ray` \| `All` | `Auto` | 控制代理客户端规则生成与同步方式 |
| `-ProxyConfigPath` | `<文件路径>` | 空 | 指定 V2Ray/Xray 的 JSON 配置文件路径，自动注入或移除 `block` 路由规则（自动生成 `.didixk-backup` 备份） |
| `-Proxy` | `<代理地址>` | 空 | 拉取在线规则列表时使用的 HTTP 代理（例如 `"http://127.0.0.1:7890"`） |
| `-SourceUrl` | `<URL1,URL2...>` | 内置多源 | 自定义在线规则源列表（多个地址以英文逗号分隔） |
| `-OfflineOnly` | 开关参数 | 关闭 | 跳过在线源拉取，仅使用同目录下的 `AdobeHosts_Offline.txt` |
| `-NoPause` | 开关参数 | 关闭 | 静默运行，结束或出错时不等待按键（适合计划任务调用） |
| `-Help` / `-h` | 开关参数 | 关闭 | 显示命令行帮助信息 |

## 目录文件说明

### 可选自定义配置文件（放置于程序同目录）

* **`AdobeHosts_Extra.txt`**：自定义额外屏蔽域名，每行一个域名（支持纯域名或 `0.0.0.0 domain` 格式，`#` 开头为注释）。
* **`AdobeFirewall_Extra.txt`**：自定义额外防火墙出站拦截目标，每行一个 `.exe` 完整路径或 IPv4 / CIDR 网段（如 `192.0.2.0/24`）。

### 自动生成与备份文件

* **`AdobeHosts_Offline.txt`**：在线拉取成功后自动缓存的本地离线规则列表。
* **`ProxyRules/`**：生成的代理客户端规则目录，包含：
  * `AdobeBlock_Clash_Provider.yaml`（Clash Classical 规则集）
  * `AdobeBlock_Clash_Merge.yaml`（Clash Verge Rev / Mihomo 全局扩展覆写配置模板）
  * `AdobeBlock_V2Ray_Routing.json`（V2Ray / Xray 路由规则片段）
  * `AdobeBlock_v2rayN_Domains.txt`（v2rayN `full:` 域名列表）
* **`AdobeHosts_ManualPaste.txt`**：当自动修改 `hosts` 失败时自动导出的纯文本规则块，方便手动粘贴。
* **`C:\Windows\System32\drivers\etc\hosts.didixk-backup`**：首次修改系统 `hosts` 前生成的原始备份文件。

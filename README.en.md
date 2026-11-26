# AdobeHostsManager

简体中文 | **English**

**AdobeHostsManager** is a single-binary Windows CLI utility designed to automate the management of **Adobe genuine-verification and telemetry blocking rules**. It integrates multi-source rule fetching with integrity validation, safe system `hosts` patching, intelligent Windows Firewall rule synchronization, and automatic rule generation/deployment for Clash, V2Ray, and v2rayN.

* **Author**: `@空影メイオウ SORAKAGEMEIOU`

* **Upstream Rule List**: ignaciocastro/a-dove-is-dumb

## Key Features

1. **Multi-Source Failover & Strict Validation**

   * Built-in primary source plus multiple CDN mirrors (Fastly, Gcore, jsDelivr, GitHub Raw) with automatic failover.

   * Validates payload size (≤ 5 MB), domain syntax, and minimum rule count (≥ 3,000 entries) to prevent corrupted or poisoned lists from being applied.

   * Compares UTC revision timestamps against the local cache (`AdobeHosts_Offline.txt`) and updates the offline cache automatically when newer online rules are fetched.

2. **Built-in Extra Domains & Custom Extensions**

   * Automatically merges and deduplicates 10 commonly missed Adobe licensing/telemetry domains (such as `genuine.adobe.com`, `prod.adobegenuine.com`, `uds.licenses.adobe.com`, and `ic.adobe.io`).

   * Supports appending custom domains via `AdobeHosts_Extra.txt` in the same directory.

3. **Safe & Lossless `hosts` Management**

   * Automatically checks privileges and triggers UAC self-elevation; creates a one-time backup (`hosts.didixk-backup`) before the first modification.

   * Preserves original file encoding (UTF-8 with/without BOM, UTF-16 LE/BE, ANSI) and attributes (Read-Only, Hidden, System), performs atomic temp-file replacement, and flushes the DNS resolver cache (`ipconfig /flushdns`).

   * Cleanly replaces both current (`DIDIXK ADOBE HOSTS`) and legacy rule blocks without touching unrelated user entries.

4. **Intelligent Windows Firewall Scanning & Sync**

   * **Smart Detection (`Auto` default)**: Scans the Windows Registry for managed (`Didixk_Adobe_Block_*`) or existing third-party Adobe outbound block rules. Rules are updated only when existing/similar rules are detected, skipping executables already covered by active rules.

   * **Service & Profile Check**: Prompts the user interactively if Adobe block rules exist while the Windows Firewall service (`MpsSvc`) or network profiles are disabled.

   * **Force Mode (`Force`)**: Enables Windows Firewall and creates outbound block rules for core Adobe executables (`AdobeGCClient.exe`, `AGMService.exe`, `AGSService.exe`, `AdobeIPCBroker.exe`, `adobe_licensing_wf.exe`, etc.), plus custom `.exe` paths or IP/CIDR ranges from `AdobeFirewall_Extra.txt`.

5. **Proxy Client Integration (Bypasses TUN / Fake-IP Limitations)**

   * Automatically detects **Clash** clients (Clash Verge Rev, Mihomo Party, Clash Nyanpasu, Mihomo) and **V2Ray / v2rayN / Xray**.

   * Generates ready-to-use rule files under `ProxyRules/`, auto-deploys providers to detected Clash `rules/` folders, and optionally injects/removes `didixk-adobe-block` routing rules directly into a V2Ray/Xray JSON config via `-ProxyConfigPath`.

6. **Built-in Diagnostics & Manual Fallback**

   * Displays detailed troubleshooting steps (AV locks, file attributes, network/proxy issues, TUN mode) upon failure and exports `AdobeHosts_ManualPaste.txt` for effortless manual patching.

## Quick Start

* **Apply / Update Rules**: Double-click `AdobeHostsManager.exe` (automatically requests Administrator elevation and updates `hosts`, firewall rules, and detected proxy rules).

* **Check Current Status**:

  ```
  AdobeHostsManager.exe -Action Status
  
  ```

* **Remove All Managed Rules**:

  ```
  AdobeHostsManager.exe -Action Remove
  
  ```

## CLI Options

| Option | Values | Default | Description | 
| ----- | ----- | ----- | ----- | 
| `-Action` | `Apply` | `Remove` | `Status` | `Apply` | Apply/update rules, remove all managed rules, or inspect current status | 
| `-FirewallMode` | `Auto` | `Force` | `Skip` | `Auto` | `Auto`: sync only if existing/similar rules exist; `Force`: enable firewall & add rules; `Skip`: ignore firewall | 
| `-ProxyMode` | `Auto` | `None` | `Clash` | `V2Ray` | `All` | `Auto` | Controls rule generation and deployment for local proxy clients | 
| `-ProxyConfigPath` | `<file_path>` | Empty | Path to a V2Ray/Xray JSON config file for direct `block` rule injection/removal (creates `.didixk-backup`) | 
| `-Proxy` | `<proxy_url>` | Empty | HTTP proxy used when fetching online rule lists (e.g., `"http://127.0.0.1:7890"`) | 
| `-SourceUrl` | `<url1,url2...>` | Built-in list | Custom comma-separated upstream rule URLs | 
| `-OfflineOnly` | Switch | Off | Skip online sources and use local `AdobeHosts_Offline.txt` directly | 
| `-NoPause` | Switch | Off | Run silently without waiting for keypress on completion or error (ideal for Task Scheduler) | 
| `-Help` / `-h` | Switch | Off | Display CLI usage help | 

## File Reference

### Optional User Configuration Files (Place Next to Executable)

* **`AdobeHosts_Extra.txt`**: Additional domains to block, one per line (supports bare domains or `0.0.0.0 domain` format; lines starting with `#` are ignored).

* **`AdobeFirewall_Extra.txt`**: Additional outbound firewall block targets, one per line (supports full `.exe` paths or IPv4 / CIDR ranges such as `192.0.2.0/24`).

### Generated & Backup Files

* **`AdobeHosts_Offline.txt`**: Local offline rule cache saved automatically after a successful online fetch.

* **`ProxyRules/`**: Generated proxy rule files:

  * `AdobeBlock_Clash_Provider.yaml` (Clash classical rule-provider payload)

  * `AdobeBlock_Clash_Merge.yaml` (Global override/merge snippet for Clash Verge Rev / Mihomo)

  * `AdobeBlock_V2Ray_Routing.json` (V2Ray / Xray routing rule object)

  * `AdobeBlock_v2rayN_Domains.txt` (`full:` domain list for v2rayN)

* **`AdobeHosts_ManualPaste.txt`**: Plain-text rule block exported automatically if `hosts` modification fails.

* **`C:\Windows\System32\drivers\etc\hosts.didixk-backup`**: Original backup of the system `hosts` file created before the first edit.

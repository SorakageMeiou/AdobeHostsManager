using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;

[assembly: AssemblyTitle("AdobeHostsManager")]
[assembly: AssemblyDescription("AdobeHostsManager")]
[assembly: AssemblyCompany("@空影メイオウ SORAKAGEMEIOU")]
[assembly: AssemblyProduct("AdobeHostsManager")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace AdobeHostsManager
{
    internal class RuleList
    {
        public string Revision { get; set; }
        public string[] Rules { get; set; }
        public string[] Domains { get; set; }
        public int Count { get; set; }
        public string RawText { get; set; }
    }

    internal class ResolvedRules
    {
        public RuleList List { get; set; }
        public bool FromOnline { get; set; }
        public string SourceLabel { get; set; }
    }

    internal class HostsData
    {
        public string Text { get; set; }
        public Encoding Encoding { get; set; }
        public byte[] Bytes { get; set; }
    }

    internal class RemoveBlocksResult
    {
        public string[] Lines { get; set; }
        public int Removed { get; set; }
    }

    internal class ProxyPresence
    {
        public bool HasClash { get; set; }
        public bool HasV2Ray { get; set; }
        public string[] ClashDirs { get; set; }
        public string[] V2RayNDirs { get; set; }
    }

    internal class ExternalFirewallRuleInfo
    {
        public string Name { get; set; }
        public bool IsActive { get; set; }
        public string ExpandedAppPath { get; set; }
        public string RemoteAddresses { get; set; }
    }

    internal class FirewallScanResult
    {
        public List<string> ManagedRuleNames = new List<string>();
        public List<ExternalFirewallRuleInfo> SimilarExternalRules = new List<ExternalFirewallRuleInfo>();

        public bool HasAnyExistingOrSimilar
        {
            get { return ManagedRuleNames.Count > 0 || SimilarExternalRules.Count > 0; }
        }
    }

    internal class FirewallStatusInfo
    {
        public bool ServiceRunning { get; set; }
        public bool DomainEnabled { get; set; }
        public bool PrivateEnabled { get; set; }
        public bool PublicEnabled { get; set; }
        public FirewallScanResult Scan { get; set; }

        public bool IsFullyEnabled
        {
            get { return ServiceRunning && DomainEnabled && PrivateEnabled && PublicEnabled; }
        }
    }

    internal class CliOptions
    {
        public string Action = "Apply";
        public string ProxyMode = "Auto";
        public string FirewallMode = "Auto"; // Auto | Force | Skip
        public string ProxyConfigPath = "";
        public bool OfflineOnly = false;
        public List<string> SourceUrls = new List<string>
        {
            "https://a.dove.isdumb.one/list.txt",
            "https://fastly.jsdelivr.net/gh/ignaciocastro/a-dove-is-dumb@latest/list.txt",
            "https://gcore.jsdelivr.net/gh/ignaciocastro/a-dove-is-dumb@latest/list.txt",
            "https://cdn.jsdelivr.net/gh/ignaciocastro/a-dove-is-dumb@latest/list.txt",
            "https://raw.githubusercontent.com/ignaciocastro/a-dove-is-dumb/main/list.txt"
        };
        public string Proxy = "";
        public bool NoPause = false;
        public bool ShowHelp = false;
    }

    internal static class Program
    {
        // ==================== 基础路径与标记（全部输出隔离至 %APPDATA%，不污染程序原目录） ====================
        private static readonly string ToolFolder = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');
        private static readonly string AppDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AdobeHostsManager"
        );
        private static readonly string OfflineListFile = Path.Combine(AppDataFolder, "AdobeHosts_Offline.txt");
        private static readonly string LegacyToolOfflineFile = Path.Combine(ToolFolder, "AdobeHosts_Offline.txt");
        private static readonly string ExtraHostsFile = Path.Combine(ToolFolder, "AdobeHosts_Extra.txt");
        private static readonly string ExtraFirewallFile = Path.Combine(ToolFolder, "AdobeFirewall_Extra.txt");
        private static readonly string ManualExportFile = Path.Combine(AppDataFolder, "AdobeHosts_ManualPaste.txt");
        private static readonly string ProxyOutputDir = Path.Combine(AppDataFolder, "ProxyRules");

        private static readonly string HostsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc");
        private static readonly string HostsFile = Path.Combine(HostsDir, "hosts");
        private static readonly string BackupFile = Path.Combine(HostsDir, "hosts.didixk-backup");

        private const string BlockBegin = "# BEGIN DIDIXK ADOBE HOSTS";
        private const string BlockEnd = "# END DIDIXK ADOBE HOSTS";
        private const string PreviousBegin = "# BEGIN ADOBE_HOSTS_AUTO_UPDATE";
        private const string PreviousEnd = "# END ADOBE_HOSTS_AUTO_UPDATE";
        private const string PreviousDateHeaderPattern = @"^#Hosts_block_Adobe_Last_update_\d{4}-\d{1,2}-\d{1,2}_[0-9:_]+_UTC(?:_By_[A-Za-z0-9.-]+)?\s*$";
        private const string V2RayRuleTag = "didixk-adobe-block";
        private const string FirewallRulePrefix = "Didixk_Adobe_Block_";

        private const string JsBlockBegin = "// BEGIN DIDIXK ADOBE BLOCK";
        private const string JsBlockEnd = "// END DIDIXK ADOBE BLOCK";
        private const string ClashProviderFileName = "AdobeBlock_Clash_Provider.yaml";
        private const string MihomoOverrideId = "didixk-adobe-block";

        // 内置补充易漏 Adobe 正版校验与遥测域名（自动合并去重）
        private static readonly string[] BuiltInExtraDomains =
        {
            "genuine.adobe.com",
            "prod.adobegenuine.com",
            "uds.licenses.adobe.com",
            "lcs-cops.adobe.io",
            "lcs-robs.adobe.io",
            "ic.adobe.io",
            "cc-api-data.adobe.io",
            "sstats.adobe.com",
            "geo2.adobe.com",
            "adobedc.demdex.net"
        };

        // 用于扫描识别类似防火墙规则的已知 Adobe 组件文件名
        private static readonly HashSet<string> KnownAdobeExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "adobegcclient.exe",
            "agmservice.exe",
            "agsservice.exe",
            "adobeipcbroker.exe",
            "adobe desktop service.exe",
            "adobe_licensing_wf.exe",
            "adobe_licensing_wf_helper.exe",
            "creative cloud.exe",
            "photoshop.exe",
            "illustrator.exe",
            "premiere pro.exe",
            "afterfx.exe",
            "acrobat.exe",
            "lightroom.exe",
            "indesign.exe",
            "audition.exe",
            "mediaencoder.exe"
        };

        private static CliOptions _opts = new CliOptions();

        [STAThread]
        private static int Main(string[] args)
        {
            try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
            try { Console.Title = "AdobeHostsManager |v1.0| @空影メイオウ SORAKAGEMEIOU"; } catch { }

            RuleList resolvedListForFallback = null;
            string resolvedSourceLabel = "";
            bool elevatedAndHandedOff = false;
            int exitCode = 0;

            try
            {
                _opts = ParseArgs(args);

                if (_opts.ShowHelp)
                {
                    PrintHelp();
                    return 0;
                }

                if (!string.Equals(_opts.Action, "Status", StringComparison.OrdinalIgnoreCase) && !TestAdministrator())
                {
                    InvokeSelfElevation(args);
                    elevatedAndHandedOff = true;
                    return 0;
                }

                if (string.Equals(_opts.Action, "Status", StringComparison.OrdinalIgnoreCase))
                {
                    RuleList local = null;
                    try { local = ReadLocalList(); } catch { }

                    HostsData hosts = GetHostsContent();
                    int blocks = RemovePriorBlocks(hosts.Text).Removed;
                    ProxyPresence proxy = TestProxyClientPresence();
                    FirewallStatusInfo fw = GetFirewallStatus();

                    string localInfo = local != null
                        ? string.Format("{0} ({1} 条)", local.Revision, local.Count)
                        : "无";
                    string hostInfo = blocks > 0
                        ? string.Format("已启用 ({0} 个区块)", blocks)
                        : "未启用";

                    List<string> proxyList = new List<string>();
                    if (proxy.HasClash) proxyList.Add("Clash");
                    if (proxy.HasV2Ray) proxyList.Add("V2Ray/v2rayN");
                    string proxyText = proxyList.Count > 0 ? string.Join(", ", proxyList.ToArray()) : "未检测到";

                    string fwRuleSummary = fw.Scan.HasAnyExistingOrSimilar
                        ? string.Format("受管 {0} 条 / 类似 {1} 条", fw.Scan.ManagedRuleNames.Count, fw.Scan.SimilarExternalRules.Count)
                        : "无相关规则";
                    string fwText = string.Format("{0} ({1})", fw.IsFullyEnabled ? "已开启" : "未完全开启", fwRuleSummary);

                    WriteColoredLine(
                        string.Format("离线列表：{0} | hosts：{1} | 防火墙：{2} | 本机代理：{3}", localInfo, hostInfo, fwText, proxyText),
                        ConsoleColor.Cyan
                    );
                }
                else if (string.Equals(_opts.Action, "Remove", StringComparison.OrdinalIgnoreCase))
                {
                    string result = UpdateHosts(null, "", true);
                    string fwNote = SyncFirewallRules(true);
                    string proxyNote = SyncProxyRules(null, true);

                    List<string> extraNotes = new List<string>();
                    if (!string.IsNullOrEmpty(fwNote)) extraNotes.Add(fwNote);
                    if (!string.IsNullOrEmpty(proxyNote)) extraNotes.Add(proxyNote);

                    WriteColoredLine(
                        result + (extraNotes.Count > 0 ? " " + string.Join("；", extraNotes.ToArray()) + "。" : ""),
                        ConsoleColor.Green
                    );
                }
                else
                {
                    ResolvedRules resolved = ResolveTargetRules();
                    resolvedListForFallback = resolved.List;
                    resolvedSourceLabel = resolved.SourceLabel;

                    string result = UpdateHosts(resolved.List, resolved.SourceLabel, false);
                    if (resolved.FromOnline)
                    {
                        SaveOfflineCache(resolved.List.RawText);
                    }

                    string fwNote = SyncFirewallRules(false);
                    string proxyNote = SyncProxyRules(resolved.List, false);

                    WriteColoredLine(result, ConsoleColor.Green);
                    if (!string.IsNullOrEmpty(fwNote))
                    {
                        WriteColoredLine(fwNote, ConsoleColor.Cyan);
                    }
                    if (!string.IsNullOrEmpty(proxyNote))
                    {
                        WriteColoredLine(proxyNote, ConsoleColor.Cyan);
                    }
                }
            }
            catch (Exception ex)
            {
                exitCode = 1;
                ShowTroubleshootingGuide(ex, resolvedListForFallback, resolvedSourceLabel);
            }
            finally
            {
                if (!elevatedAndHandedOff && !_opts.NoPause && !_opts.ShowHelp)
                {
                    if (exitCode != 0)
                    {
                        Console.WriteLine();
                        Console.Write("按回车键退出");
                        try { Console.ReadLine(); } catch { }
                    }
                    else
                    {
                        Thread.Sleep(2000);
                    }
                }
            }

            return exitCode;
        }

        // ==================== 参数解析 ====================
        private static CliOptions ParseArgs(string[] args)
        {
            CliOptions opts = new CliOptions();
            bool customUrlsProvided = false;

            for (int i = 0; i < args.Length; i++)
            {
                string key = args[i].TrimStart('-', '/').ToLowerInvariant();
                switch (key)
                {
                    case "h":
                    case "help":
                    case "?":
                        opts.ShowHelp = true;
                        break;

                    case "action":
                        if (i + 1 >= args.Length) throw new ArgumentException("参数 -Action 缺少值（Apply | Remove | Status）。");
                        string act = args[++i];
                        if (string.Equals(act, "Apply", StringComparison.OrdinalIgnoreCase)) opts.Action = "Apply";
                        else if (string.Equals(act, "Remove", StringComparison.OrdinalIgnoreCase)) opts.Action = "Remove";
                        else if (string.Equals(act, "Status", StringComparison.OrdinalIgnoreCase)) opts.Action = "Status";
                        else throw new ArgumentException("无效的 -Action 参数值：" + act + "（仅支持 Apply | Remove | Status）。");
                        break;

                    case "proxymode":
                        if (i + 1 >= args.Length) throw new ArgumentException("参数 -ProxyMode 缺少值（Auto | None | Clash | V2Ray | All）。");
                        string pm = args[++i];
                        if (string.Equals(pm, "Auto", StringComparison.OrdinalIgnoreCase)) opts.ProxyMode = "Auto";
                        else if (string.Equals(pm, "None", StringComparison.OrdinalIgnoreCase)) opts.ProxyMode = "None";
                        else if (string.Equals(pm, "Clash", StringComparison.OrdinalIgnoreCase)) opts.ProxyMode = "Clash";
                        else if (string.Equals(pm, "V2Ray", StringComparison.OrdinalIgnoreCase)) opts.ProxyMode = "V2Ray";
                        else if (string.Equals(pm, "All", StringComparison.OrdinalIgnoreCase)) opts.ProxyMode = "All";
                        else throw new ArgumentException("无效的 -ProxyMode 参数值：" + pm + "（仅支持 Auto | None | Clash | V2Ray | All）。");
                        break;

                    case "firewallmode":
                        if (i + 1 >= args.Length) throw new ArgumentException("参数 -FirewallMode 缺少值（Auto | Force | Skip）。");
                        string fm = args[++i];
                        if (string.Equals(fm, "Auto", StringComparison.OrdinalIgnoreCase)) opts.FirewallMode = "Auto";
                        else if (string.Equals(fm, "Force", StringComparison.OrdinalIgnoreCase)) opts.FirewallMode = "Force";
                        else if (string.Equals(fm, "Skip", StringComparison.OrdinalIgnoreCase)) opts.FirewallMode = "Skip";
                        else throw new ArgumentException("无效的 -FirewallMode 参数值：" + fm + "（仅支持 Auto | Force | Skip）。");
                        break;

                    case "proxyconfigpath":
                        if (i + 1 >= args.Length) throw new ArgumentException("参数 -ProxyConfigPath 缺少文件路径。");
                        opts.ProxyConfigPath = args[++i];
                        break;

                    case "offlineonly":
                        opts.OfflineOnly = true;
                        break;

                    case "sourceurl":
                        if (i + 1 >= args.Length) throw new ArgumentException("参数 -SourceUrl 缺少 URL。");
                        if (!customUrlsProvided)
                        {
                            opts.SourceUrls.Clear();
                            customUrlsProvided = true;
                        }
                        string[] parts = args[++i].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string u in parts)
                        {
                            string trimmed = u.Trim();
                            if (!string.IsNullOrEmpty(trimmed)) opts.SourceUrls.Add(trimmed);
                        }
                        break;

                    case "proxy":
                        if (i + 1 >= args.Length) throw new ArgumentException("参数 -Proxy 缺少代理地址。");
                        opts.Proxy = args[++i];
                        break;

                    case "nopause":
                        opts.NoPause = true;
                        break;

                    default:
                        throw new ArgumentException("未知参数：" + args[i] + "（使用 -Help 查看可用参数）。");
                }
            }

            return opts;
        }

        private static void PrintHelp()
        {
            Console.WriteLine("AdobeHostsManager");
            Console.WriteLine("作者：@空影メイオウ SORAKAGEMEIOU");
            Console.WriteLine();
            Console.WriteLine("用法示例：");
            Console.WriteLine("  AdobeHostsManager.exe                                  自动更新 hosts、防火墙及本机代理软件规则");
            Console.WriteLine("  AdobeHostsManager.exe -Action Status                   查看当前 hosts、防火墙规则与离线列表状态");
            Console.WriteLine("  AdobeHostsManager.exe -Action Remove                   移除受管 hosts、防火墙及自动注入的代理规则");
            Console.WriteLine("  AdobeHostsManager.exe -FirewallMode Auto|Force|Skip    Auto=有类似规则才更新 | Force=强制添加 | Skip=跳过");
            Console.WriteLine("  AdobeHostsManager.exe -ProxyMode Auto|Clash|V2Ray|None 自动注入 Clash / V2Ray 拦截规则（输出存于 AppData）");
            Console.WriteLine("  AdobeHostsManager.exe -Proxy \"http://127.0.0.1:7890\"   通过 HTTP 代理拉取在线规则");
            Console.WriteLine("  AdobeHostsManager.exe -OfflineOnly                     跳过在线源，直接使用本地离线列表");
            Console.WriteLine("  AdobeHostsManager.exe -NoPause                         静默运行，结束或出错时不等待按键");
        }

        // ==================== 权限检查与自动提权 ====================
        private static bool TestAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static void InvokeSelfElevation(string[] rawArgs)
        {
            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            List<string> escapedArgs = new List<string>();
            foreach (string a in rawArgs)
            {
                if (a.IndexOf(' ') >= 0 || a.IndexOf('"') >= 0)
                {
                    escapedArgs.Add("\"" + a.Replace("\"", "\\\"") + "\"");
                }
                else
                {
                    escapedArgs.Add(a);
                }
            }

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = string.Join(" ", escapedArgs.ToArray()),
                WorkingDirectory = ToolFolder,
                Verb = "runas",
                UseShellExecute = true
            };

            try
            {
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC 提权被取消或失败：" + ex.Message, ex);
            }
        }

        // ==================== 规则校验、额外域名融合与多源拉取 ====================
        private static RuleList TestRules(string content)
        {
            if (string.IsNullOrWhiteSpace(content) || content.Length > 5000000)
            {
                throw new InvalidDataException("规则列表为空或超过 5MB 安全限制。");
            }

            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> validated = new List<string>();
            List<string> domains = new List<string>();
            string revision = "未标注";

            Regex revRegex = new Regex(@"^#\s*Last update:\s*(.+)$");
            Regex ruleRegex = new Regex(@"^0\.0\.0\.0\s+([A-Za-z0-9.-]+)$");
            Regex domainRegex = new Regex(@"^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+$");

            string[] lines = content.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0) continue;

                Match revMatch = revRegex.Match(line);
                if (revMatch.Success)
                {
                    revision = revMatch.Groups[1].Value.Trim();
                    continue;
                }

                if (line.StartsWith("#", StringComparison.Ordinal)) continue;

                Match ruleMatch = ruleRegex.Match(line);
                if (!ruleMatch.Success)
                {
                    throw new InvalidDataException("规则列表包含非预期内容：" + line.Substring(0, Math.Min(60, line.Length)));
                }

                string domain = ruleMatch.Groups[1].Value.ToLowerInvariant();
                if (domain.Length > 253 || !domainRegex.IsMatch(domain))
                {
                    throw new InvalidDataException("规则列表存在无效域名：" + domain);
                }

                if (unique.Add(domain))
                {
                    domains.Add(domain);
                    validated.Add("0.0.0.0 " + domain);
                }
            }

            if (validated.Count < 3000)
            {
                throw new InvalidDataException(string.Format("规则数量异常（仅 {0} 条，低于安全阈值 3000 条）。", validated.Count));
            }

            MergeExtraDomains(unique, domains, validated, domainRegex);

            return new RuleList
            {
                Revision = revision,
                Rules = validated.ToArray(),
                Domains = domains.ToArray(),
                Count = validated.Count,
                RawText = content
            };
        }

        private static void MergeExtraDomains(HashSet<string> unique, List<string> domains, List<string> validated, Regex domainRegex)
        {
            foreach (string d in BuiltInExtraDomains)
            {
                string norm = d.Trim().ToLowerInvariant();
                if (norm.Length > 0 && norm.Length <= 253 && domainRegex.IsMatch(norm) && unique.Add(norm))
                {
                    domains.Add(norm);
                    validated.Add("0.0.0.0 " + norm);
                }
            }

            string[] extraPaths = { Path.Combine(AppDataFolder, "AdobeHosts_Extra.txt"), ExtraHostsFile };
            foreach (string path in extraPaths)
            {
                if (!File.Exists(path)) continue;
                try
                {
                    string[] extraLines = File.ReadAllLines(path, Encoding.UTF8);
                    foreach (string raw in extraLines)
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

                        if (line.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                            line.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase))
                        {
                            string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2) line = parts[1].Trim();
                        }

                        string norm = line.ToLowerInvariant();
                        if (norm.Length > 0 && norm.Length <= 253 && domainRegex.IsMatch(norm) && unique.Add(norm))
                        {
                            domains.Add(norm);
                            validated.Add("0.0.0.0 " + norm);
                        }
                    }
                }
                catch { }
            }
        }

        private static DateTime? ParseRevisionDate(string revision)
        {
            if (string.IsNullOrEmpty(revision)) return null;
            Match m = Regex.Match(revision, @"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+UTC$");
            if (m.Success)
            {
                DateTime dt;
                if (DateTime.TryParseExact(m.Groups[1].Value, "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
                {
                    return dt;
                }
            }
            return null;
        }

        private static RuleList ReadLocalList()
        {
            if (File.Exists(OfflineListFile))
            {
                return TestRules(File.ReadAllText(OfflineListFile, Encoding.UTF8));
            }
            if (File.Exists(LegacyToolOfflineFile))
            {
                return TestRules(File.ReadAllText(LegacyToolOfflineFile, Encoding.UTF8));
            }
            return null;
        }

        private static ResolvedRules GetOnlineListWithFailover()
        {
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12 | (SecurityProtocolType)12288;
            }
            catch
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            }

            string lastError = "";
            foreach (string url in _opts.SourceUrls)
            {
                if (string.IsNullOrWhiteSpace(url)) continue;
                try
                {
                    HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                    req.Method = "GET";
                    req.Timeout = 12000;
                    req.ReadWriteTimeout = 12000;
                    req.AllowAutoRedirect = true;
                    req.MaximumAutomaticRedirections = 3;
                    req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdobeHostsManager/1.0";

                    if (!string.IsNullOrWhiteSpace(_opts.Proxy))
                    {
                        req.Proxy = new WebProxy(_opts.Proxy);
                    }

                    using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    using (Stream stream = resp.GetResponseStream())
                    using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                    {
                        string content = reader.ReadToEnd();
                        RuleList list = TestRules(content);
                        return new ResolvedRules
                        {
                            List = list,
                            FromOnline = true,
                            SourceLabel = url
                        };
                    }
                }
                catch (Exception ex)
                {
                    lastError = url + " -> " + ex.Message;
                }
            }

            throw new WebException("所有在线源及 CDN 镜像均无法访问（最后错误：" + lastError + "）。");
        }

        private static void SaveOfflineCache(string rawText)
        {
            Directory.CreateDirectory(AppDataFolder);
            string tmp = Path.Combine(AppDataFolder, "AdobeHosts_Offline." + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                File.WriteAllText(tmp, rawText, new UTF8Encoding(false));
                File.Copy(tmp, OfflineListFile, true);
            }
            catch { }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        }

        private static ResolvedRules ResolveTargetRules()
        {
            RuleList local = null;
            try { local = ReadLocalList(); } catch { }

            if (_opts.OfflineOnly)
            {
                if (local == null)
                {
                    throw new FileNotFoundException("已指定 -OfflineOnly，但 AppData 缓存或程序目录中缺少有效的 AdobeHosts_Offline.txt。");
                }
                return new ResolvedRules
                {
                    List = local,
                    FromOnline = false,
                    SourceLabel = "本地离线列表"
                };
            }

            try
            {
                ResolvedRules online = GetOnlineListWithFailover();
                if (local != null)
                {
                    DateTime? localDate = ParseRevisionDate(local.Revision);
                    DateTime? remoteDate = ParseRevisionDate(online.List.Revision);
                    if (localDate.HasValue && remoteDate.HasValue && remoteDate.Value < localDate.Value)
                    {
                        return new ResolvedRules
                        {
                            List = local,
                            FromOnline = false,
                            SourceLabel = "本地离线列表（较新）"
                        };
                    }
                }
                return online;
            }
            catch (Exception ex)
            {
                if (local != null)
                {
                    return new ResolvedRules
                    {
                        List = local,
                        FromOnline = false,
                        SourceLabel = "本地离线列表（自动回退）"
                    };
                }
                throw new InvalidOperationException("在线拉取失败且缺少可用的离线列表 AdobeHosts_Offline.txt。" + ex.Message, ex);
            }
        }

        // ==================== Windows 防火墙扫描、状态检测与智能同步 ====================
        private static bool IsRegistryFirewallProfileEnabled(string subKeyPath)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKeyPath, false))
                {
                    if (key == null) return true;
                    object val = key.GetValue("EnableFirewall");
                    if (val == null) return true;
                    return Convert.ToInt32(val) != 0;
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool IsMpsSvcRunning()
        {
            try
            {
                string output = RunCommandAndCapture("sc.exe", "query MpsSvc");
                return output.IndexOf(": 4", StringComparison.Ordinal) >= 0;
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeFilePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            try
            {
                string expanded = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
                return Path.GetFullPath(expanded).TrimEnd('\\');
            }
            catch
            {
                return path.Trim().Trim('"');
            }
        }

        private static FirewallScanResult ScanAdobeFirewallRules()
        {
            FirewallScanResult result = new FirewallScanResult();
            HashSet<string> seenManagedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", false))
                {
                    if (key == null) return result;

                    foreach (string valueName in key.GetValueNames())
                    {
                        string data = Convert.ToString(key.GetValue(valueName));
                        if (string.IsNullOrEmpty(data)) continue;

                        string action = "";
                        string dir = "";
                        string active = "TRUE";
                        string app = "";
                        string name = "";
                        List<string> remoteAddrs = new List<string>();

                        string[] tokens = data.Split('|');
                        foreach (string token in tokens)
                        {
                            int eqIdx = token.IndexOf('=');
                            if (eqIdx <= 0) continue;

                            string k = token.Substring(0, eqIdx);
                            string v = token.Substring(eqIdx + 1);

                            if (string.Equals(k, "Action", StringComparison.OrdinalIgnoreCase)) action = v;
                            else if (string.Equals(k, "Dir", StringComparison.OrdinalIgnoreCase)) dir = v;
                            else if (string.Equals(k, "Active", StringComparison.OrdinalIgnoreCase)) active = v;
                            else if (string.Equals(k, "App", StringComparison.OrdinalIgnoreCase)) app = v;
                            else if (string.Equals(k, "Name", StringComparison.OrdinalIgnoreCase)) name = v;
                            else if (string.Equals(k, "RA4", StringComparison.OrdinalIgnoreCase) ||
                                     string.Equals(k, "RA6", StringComparison.OrdinalIgnoreCase))
                            {
                                remoteAddrs.Add(v);
                            }
                        }

                        if (name.StartsWith(FirewallRulePrefix, StringComparison.OrdinalIgnoreCase))
                        {
                            if (seenManagedNames.Add(name))
                            {
                                result.ManagedRuleNames.Add(name);
                            }
                            continue;
                        }

                        if (string.Equals(action, "Block", StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(dir, "Out", StringComparison.OrdinalIgnoreCase))
                        {
                            string normalizedApp = NormalizeFilePath(app);
                            string appFileName = "";
                            if (!string.IsNullOrEmpty(normalizedApp))
                            {
                                try { appFileName = Path.GetFileName(normalizedApp); } catch { }
                            }

                            bool matchesApp =
                                (!string.IsNullOrEmpty(normalizedApp) &&
                                 (normalizedApp.IndexOf(@"\Adobe\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                  normalizedApp.IndexOf(@"\AdobeGCClient\", StringComparison.OrdinalIgnoreCase) >= 0)) ||
                                (!string.IsNullOrEmpty(appFileName) && KnownAdobeExeNames.Contains(appFileName));

                            bool matchesName =
                                !string.IsNullOrEmpty(name) &&
                                !name.StartsWith("@", StringComparison.Ordinal) &&
                                (name.IndexOf("adobe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 name.IndexOf("didixk", StringComparison.OrdinalIgnoreCase) >= 0);

                            if (matchesApp || matchesName)
                            {
                                result.SimilarExternalRules.Add(new ExternalFirewallRuleInfo
                                {
                                    Name = name,
                                    IsActive = string.Equals(active, "TRUE", StringComparison.OrdinalIgnoreCase),
                                    ExpandedAppPath = normalizedApp,
                                    RemoteAddresses = string.Join(",", remoteAddrs.ToArray())
                                });
                            }
                        }
                    }
                }
            }
            catch { }

            return result;
        }

        private static FirewallStatusInfo GetFirewallStatus()
        {
            return new FirewallStatusInfo
            {
                ServiceRunning = IsMpsSvcRunning(),
                DomainEnabled = IsRegistryFirewallProfileEnabled(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
                PrivateEnabled = IsRegistryFirewallProfileEnabled(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
                PublicEnabled = IsRegistryFirewallProfileEnabled(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"),
                Scan = ScanAdobeFirewallRules()
            };
        }

        private static bool PromptUserToEnableFirewall(FirewallStatusInfo status)
        {
            Console.WriteLine();
            WriteColoredLine("--------------------------------------------------------------------", ConsoleColor.Yellow);
            WriteColoredLine("[提示] 检测到防火墙中存在 Adobe 拦截规则，但 Windows 防火墙未完全开启：", ConsoleColor.Yellow);
            Console.WriteLine(string.Format("       防火墙服务 (MpsSvc)：{0}", status.ServiceRunning ? "运行中" : "已停止"));
            Console.WriteLine(string.Format("       域网络：{0} | 专用网络：{1} | 公用网络：{2}",
                status.DomainEnabled ? "开启" : "关闭",
                status.PrivateEnabled ? "开启" : "关闭",
                status.PublicEnabled ? "开启" : "关闭"));
            Console.WriteLine("       若不开启防火墙，已有的 Adobe 出站拦截规则将无法生效。");
            WriteColoredLine("--------------------------------------------------------------------", ConsoleColor.Yellow);

            while (true)
            {
                Console.Write("是否立即开启 Windows 防火墙并更新最新拦截规则？请输入 yes 或 no（按回车确认）：");
                string input = Console.ReadLine();
                if (input == null) return false;

                string trimmed = input.Trim().ToLowerInvariant();
                if (trimmed == "yes" || trimmed == "y")
                {
                    return true;
                }
                if (trimmed == "no" || trimmed == "n")
                {
                    return false;
                }

                WriteColoredLine("输入无效，请使用键盘输入 yes 或 no 后按回车。", ConsoleColor.DarkYellow);
            }
        }

        private static void EnableWindowsFirewall()
        {
            RunCommandAndCapture("sc.exe", "config MpsSvc start= auto");
            RunCommandAndCapture("net.exe", "start MpsSvc");
            RunCommandAndCapture("netsh.exe", "advfirewall set allprofiles state on");

            FirewallStatusInfo after = GetFirewallStatus();
            if (!after.IsFullyEnabled)
            {
                throw new InvalidOperationException("尝试开启 Windows 防火墙失败，可能被组策略或第三方安全软件接管锁定。");
            }
        }

        private static void RemoveManagedFirewallRules(List<string> managedRuleNames)
        {
            foreach (string ruleName in managedRuleNames)
            {
                string safeName = ruleName.Replace("\"", "");
                RunCommandAndCapture("netsh.exe", string.Format("advfirewall firewall delete rule name=\"{0}\"", safeName));
            }
        }

        private static List<string> CollectTargetAdobeExecutables()
        {
            HashSet<string> uniquePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> result = new List<string>();

            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            string[] relativeCandidates =
            {
                @"Common Files\Adobe\AdobeGCClient\AdobeGCClient.exe",
                @"Common Files\Adobe\AdobeGCClient\AGMService.exe",
                @"Common Files\Adobe\AdobeGCClient\AGSService.exe",
                @"Common Files\Adobe\OOBE\PDApp\IPC\AdobeIPCBroker.exe",
                @"Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe",
                @"Common Files\Adobe\Adobe Desktop Common\NGL\adobe_licensing_wf.exe",
                @"Common Files\Adobe\Adobe Desktop Common\NGL\adobe_licensing_wf_helper.exe",
                @"Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe"
            };

            string[] roots = { pf, pf86 };
            foreach (string root in roots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                foreach (string rel in relativeCandidates)
                {
                    string full = NormalizeFilePath(Path.Combine(root, rel));
                    if (File.Exists(full) && uniquePaths.Add(full))
                    {
                        result.Add(full);
                    }
                }

                string adobeDir = Path.Combine(root, "Adobe");
                if (Directory.Exists(adobeDir))
                {
                    try
                    {
                        foreach (string subDir in Directory.GetDirectories(adobeDir))
                        {
                            string[] extraNames = { "adobe_licensing_wf.exe", "adobe_licensing_wf_helper.exe", "AdobeGCClient.exe" };
                            foreach (string exeName in extraNames)
                            {
                                string candidate = NormalizeFilePath(Path.Combine(subDir, exeName));
                                if (File.Exists(candidate) && uniquePaths.Add(candidate))
                                {
                                    result.Add(candidate);
                                }
                            }
                        }
                    }
                    catch { }
                }
            }

            return result;
        }

        private static void LoadExtraFirewallTargets(List<string> exePaths, List<string> ipRanges)
        {
            string[] extraPaths = { Path.Combine(AppDataFolder, "AdobeFirewall_Extra.txt"), ExtraFirewallFile };
            HashSet<string> existingExes = new HashSet<string>(exePaths, StringComparer.OrdinalIgnoreCase);
            Regex ipOrCidrRegex = new Regex(@"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$");

            foreach (string path in extraPaths)
            {
                if (!File.Exists(path)) continue;
                try
                {
                    string[] lines = File.ReadAllLines(path, Encoding.UTF8);
                    foreach (string raw in lines)
                    {
                        string line = raw.Trim().Trim('"');
                        if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

                        if (ipOrCidrRegex.IsMatch(line))
                        {
                            ipRanges.Add(line);
                        }
                        else if (line.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            string normalized = NormalizeFilePath(line);
                            if (File.Exists(normalized) && existingExes.Add(normalized))
                            {
                                exePaths.Add(normalized);
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private static string SyncFirewallRules(bool removeOnly)
        {
            if (string.Equals(_opts.FirewallMode, "Skip", StringComparison.OrdinalIgnoreCase))
            {
                return "";
            }

            FirewallStatusInfo status = GetFirewallStatus();
            FirewallScanResult scan = status.Scan;

            if (removeOnly)
            {
                if (scan.ManagedRuleNames.Count == 0) return "";
                RemoveManagedFirewallRules(scan.ManagedRuleNames);
                return string.Format("已移除 {0} 条受管 Windows 防火墙拦截规则", scan.ManagedRuleNames.Count);
            }

            bool isForce = string.Equals(_opts.FirewallMode, "Force", StringComparison.OrdinalIgnoreCase);

            if (!isForce && !scan.HasAnyExistingOrSimilar)
            {
                return "Windows 防火墙未检测到已有或类似 Adobe 拦截规则，已跳过新增";
            }

            if (!status.IsFullyEnabled)
            {
                bool shouldEnable;
                if (isForce)
                {
                    shouldEnable = true;
                }
                else if (_opts.NoPause)
                {
                    return "检测到已有 Adobe 防火墙规则，但防火墙未开启（静默模式已跳过）";
                }
                else
                {
                    shouldEnable = PromptUserToEnableFirewall(status);
                }

                if (!shouldEnable)
                {
                    return "已根据选择跳过 Windows 防火墙规则更新";
                }

                EnableWindowsFirewall();
                WriteColoredLine("Windows 防火墙已成功开启。", ConsoleColor.Green);
            }

            HashSet<string> alreadyCoveredActiveApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ExternalFirewallRuleInfo ext in scan.SimilarExternalRules)
            {
                if (ext.IsActive && !string.IsNullOrEmpty(ext.ExpandedAppPath))
                {
                    alreadyCoveredActiveApps.Add(ext.ExpandedAppPath);
                }
            }

            if (scan.ManagedRuleNames.Count > 0)
            {
                RemoveManagedFirewallRules(scan.ManagedRuleNames);
            }

            List<string> targetExes = CollectTargetAdobeExecutables();
            List<string> targetIps = new List<string>();
            LoadExtraFirewallTargets(targetExes, targetIps);

            int addedCount = 0;
            int keptExternalCount = 0;

            for (int i = 0; i < targetExes.Count; i++)
            {
                string exePath = targetExes[i];
                if (alreadyCoveredActiveApps.Contains(exePath))
                {
                    keptExternalCount++;
                    continue;
                }

                string baseName = Path.GetFileNameWithoutExtension(exePath).Replace(" ", "_");
                string ruleName = string.Format("{0}App_{1}_{2}", FirewallRulePrefix, i + 1, baseName);
                string args = string.Format(
                    "advfirewall firewall add rule name=\"{0}\" dir=out action=block program=\"{1}\" enable=yes profile=any",
                    ruleName,
                    exePath
                );
                RunCommandAndCapture("netsh.exe", args);
                addedCount++;
            }

            if (targetIps.Count > 0)
            {
                string ipList = string.Join(",", targetIps.ToArray());
                string ruleName = FirewallRulePrefix + "Custom_RemoteIPs";
                string args = string.Format(
                    "advfirewall firewall add rule name=\"{0}\" dir=out action=block remoteip={1} enable=yes profile=any",
                    ruleName,
                    ipList
                );
                RunCommandAndCapture("netsh.exe", args);
                addedCount++;
            }

            if (addedCount == 0 && keptExternalCount > 0)
            {
                return string.Format("Windows 防火墙扫描到 {0} 条已有拦截规则且已完整覆盖最新组件，无需额外添加", keptExternalCount);
            }

            if (addedCount == 0)
            {
                return "Windows 防火墙已更新（本机未检测到需要新增拦截的 Adobe 组件）";
            }

            return string.Format(
                "Windows 防火墙已更新至最新规则（写入 {0} 条{1}）",
                addedCount,
                keptExternalCount > 0 ? string.Format("，保留已有有效规则 {0} 条", keptExternalCount) : ""
            );
        }

        private static string RunCommandAndCapture(string fileName, string arguments)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process p = Process.Start(psi))
            {
                if (p == null) return "";
                string stdout = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
                return stdout ?? "";
            }
        }

        // ==================== hosts 读写与区块管理 ====================
        private static HostsData GetHostsContent()
        {
            if (!File.Exists(HostsFile))
            {
                throw new FileNotFoundException("找不到系统 hosts 文件：" + HostsFile);
            }

            byte[] bytes = File.ReadAllBytes(HostsFile);
            Encoding encoding;
            string text;

            if (bytes.Length >= 3 && bytes[0] == 239 && bytes[1] == 187 && bytes[2] == 191)
            {
                encoding = new UTF8Encoding(true);
                text = new UTF8Encoding(false).GetString(bytes, 3, bytes.Length - 3);
            }
            else if (bytes.Length >= 2 && bytes[0] == 255 && bytes[1] == 254)
            {
                encoding = Encoding.Unicode;
                text = encoding.GetString(bytes, 2, bytes.Length - 2);
            }
            else if (bytes.Length >= 2 && bytes[0] == 254 && bytes[1] == 255)
            {
                encoding = Encoding.BigEndianUnicode;
                text = encoding.GetString(bytes, 2, bytes.Length - 2);
            }
            else
            {
                try
                {
                    text = new UTF8Encoding(false, true).GetString(bytes);
                    encoding = new UTF8Encoding(false);
                }
                catch
                {
                    encoding = Encoding.Default;
                    text = encoding.GetString(bytes);
                }
            }

            return new HostsData { Text = text, Encoding = encoding, Bytes = bytes };
        }

        private static RemoveBlocksResult RemovePriorBlocks(string text)
        {
            List<string> retained = new List<string>();
            string activeEnd = null;
            bool oldDatedBlock = false;
            int removedCount = 0;

            Regex oldHeaderRegex = new Regex(PreviousDateHeaderPattern);
            Regex oldEntryRegex = new Regex(@"^0\.0\.0\.0\s+[A-Za-z0-9.-]+\s*$");

            string[] lines = text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
            foreach (string line in lines)
            {
                string trim = line.Trim();
                if (activeEnd != null)
                {
                    if (trim == activeEnd) activeEnd = null;
                    continue;
                }
                if (trim == BlockBegin)
                {
                    removedCount++;
                    activeEnd = BlockEnd;
                    oldDatedBlock = false;
                    continue;
                }
                if (trim == PreviousBegin)
                {
                    removedCount++;
                    activeEnd = PreviousEnd;
                    oldDatedBlock = false;
                    continue;
                }
                if (oldHeaderRegex.IsMatch(trim))
                {
                    removedCount++;
                    oldDatedBlock = true;
                    continue;
                }
                if (oldDatedBlock)
                {
                    if (oldEntryRegex.IsMatch(trim) || trim.Length == 0) continue;
                    oldDatedBlock = false;
                }
                retained.Add(line);
            }

            if (activeEnd != null)
            {
                throw new InvalidDataException("检测到 hosts 中存在不完整的旧规则区块（缺少结束标记 " + activeEnd + "），为防止误删其他配置已终止操作。");
            }

            while (retained.Count > 0 && string.IsNullOrWhiteSpace(retained[retained.Count - 1]))
            {
                retained.RemoveAt(retained.Count - 1);
            }

            return new RemoveBlocksResult { Lines = retained.ToArray(), Removed = removedCount };
        }

        private static string[] BuildRuleBlockLines(RuleList list, string sourceLabel)
        {
            List<string> lines = new List<string>(list.Rules.Length + 6);
            lines.Add(BlockBegin);
            lines.Add("# Author: @空影メイオウ SORAKAGEMEIOU");
            lines.Add("# Upstream: https://github.com/ignaciocastro/a-dove-is-dumb | Source: " + sourceLabel);
            lines.Add("# List update: " + list.Revision);
            lines.AddRange(list.Rules);
            lines.Add(BlockEnd);
            return lines.ToArray();
        }

        private static bool ExportManualRuleFile(RuleList list, string sourceLabel)
        {
            if (list == null) return false;
            try
            {
                Directory.CreateDirectory(AppDataFolder);
                string blockText = string.Join("\r\n", BuildRuleBlockLines(list, sourceLabel));
                File.WriteAllText(ManualExportFile, blockText + "\r\n", new UTF8Encoding(false));
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string UpdateHosts(RuleList list, string sourceLabel, bool removeOnly)
        {
            HostsData original = GetHostsContent();
            RemoveBlocksResult prepared = RemovePriorBlocks(original.Text);

            if (removeOnly && prepared.Removed == 0)
            {
                return "完成：未发现受管 hosts 规则，无需修改。";
            }

            List<string> outLines = new List<string>(prepared.Lines);
            if (!removeOnly)
            {
                if (outLines.Count > 0) outLines.Add("");
                outLines.AddRange(BuildRuleBlockLines(list, sourceLabel));
            }

            string newText = string.Join("\r\n", outLines.ToArray()) + "\r\n";
            if (newText == original.Text)
            {
                return string.Format("完成：hosts 已是最新（版本：{0}，共 {1} 条规则）。", list.Revision, list.Count);
            }

            if (!File.Exists(BackupFile))
            {
                File.WriteAllBytes(BackupFile, original.Bytes);
            }

            FileAttributes origAttributes = File.GetAttributes(HostsFile);
            FileAttributes restrictedMask = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System;
            bool hadRestricted = (origAttributes & restrictedMask) != 0;
            string tempFile = Path.Combine(HostsDir, "hosts.didixk-temp-" + Guid.NewGuid().ToString("N"));

            try
            {
                if (hadRestricted)
                {
                    File.SetAttributes(HostsFile, origAttributes & ~restrictedMask);
                }

                File.WriteAllText(tempFile, newText, original.Encoding);
                try
                {
                    File.Copy(tempFile, HostsFile, true);
                }
                catch
                {
                    try { File.WriteAllBytes(HostsFile, original.Bytes); } catch { }
                    throw;
                }
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                if (hadRestricted)
                {
                    try { File.SetAttributes(HostsFile, origAttributes); } catch { }
                }
            }

            FlushDns();

            if (removeOnly)
            {
                return "完成：已移除 Adobe hosts 规则并刷新 DNS。";
            }
            return string.Format("完成：已写入 {0} 条 hosts 规则（版本：{1}）并刷新 DNS。", list.Count, list.Revision);
        }

        private static void FlushDns()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "ipconfig.exe",
                    Arguments = "/flushdns",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (Process p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(5000);
                }
            }
            catch { }
        }

        // ==================== 代理客户端（Clash / Mihomo Party / v2rayN）全自动规则注入 ====================
        private static string[] GetDetectedClashDirs()
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            string[] candidates =
            {
                Path.Combine(appData, "io.github.clash-verge-rev.clash-verge-rev"),
                Path.Combine(appData, "mihomo-party"),
                Path.Combine(appData, "clash-party"),
                Path.Combine(appData, "clash-nyanpasu"),
                Path.Combine(appData, "Clash Nyanpasu"),
                Path.Combine(localAppData, "Clash Nyanpasu", "data"),
                Path.Combine(appData, "flclash"),
                Path.Combine(userProfile, @".config\clash"),
                Path.Combine(userProfile, @".config\mihomo")
            };

            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> found = new List<string>();
            foreach (string dir in candidates)
            {
                if (Directory.Exists(dir) && unique.Add(dir))
                {
                    found.Add(dir);
                }
            }
            return found.ToArray();
        }

        private static string[] GetDetectedV2RayNDirs()
        {
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> found = new List<string>();

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            string[] candidates =
            {
                Path.Combine(appData, "v2rayN"),
                Path.Combine(localAppData, "v2rayN")
            };

            foreach (string dir in candidates)
            {
                if (Directory.Exists(dir) && unique.Add(dir))
                {
                    found.Add(dir);
                }
            }

            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        if (string.Equals(p.ProcessName, "v2rayN", StringComparison.OrdinalIgnoreCase))
                        {
                            string exePath = p.MainModule.FileName;
                            string dir = Path.GetDirectoryName(exePath);
                            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && unique.Add(dir))
                            {
                                found.Add(dir);
                            }
                        }
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            return found.ToArray();
        }

        private static ProxyPresence TestProxyClientPresence()
        {
            string[] clashDirs = GetDetectedClashDirs();
            string[] v2rayNDirs = GetDetectedV2RayNDirs();
            bool hasClashProc = false;
            bool hasV2RayProc = false;

            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        string name = p.ProcessName.ToLowerInvariant();
                        if (name.Contains("clash") || name.Contains("mihomo") || name.Contains("flclash")) hasClashProc = true;
                        if (name.Contains("v2ray") || name.Contains("xray")) hasV2RayProc = true;
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            bool hasClash = (clashDirs.Length > 0) || hasClashProc;
            bool hasV2Ray = (v2rayNDirs.Length > 0) || hasV2RayProc || !string.IsNullOrWhiteSpace(_opts.ProxyConfigPath);

            return new ProxyPresence
            {
                HasClash = hasClash,
                HasV2Ray = hasV2Ray,
                ClashDirs = clashDirs,
                V2RayNDirs = v2rayNDirs
            };
        }

        private static string BuildClashProviderContent(RuleList list)
        {
            List<string> providerLines = new List<string>(list.Domains.Length + 4);
            providerLines.Add("# Author: @空影メイオウ SORAKAGEMEIOU");
            providerLines.Add(string.Format("# List update: {0} | Count: {1}", list.Revision, list.Count));
            providerLines.Add("payload:");
            foreach (string d in list.Domains)
            {
                providerLines.Add("  - 'DOMAIN," + d + "'");
            }
            return string.Join("\r\n", providerLines.ToArray()) + "\r\n";
        }

        private static string BuildMihomoPlusOverrideYaml()
        {
            return string.Join("\r\n", new[]
            {
                "# Author: @空影メイオウ SORAKAGEMEIOU",
                "# 适用于 Mihomo Party / Clash Party 全局或订阅覆写（使用 +rules 插入规则列表最顶部）",
                "use-system-hosts: true",
                "",
                "rule-providers:",
                "  didixk-adobe-block:",
                "    type: file",
                "    behavior: classical",
                "    path: \"./rules/" + ClashProviderFileName + "\"",
                "",
                "+rules:",
                "  - RULE-SET,didixk-adobe-block,REJECT",
                ""
            });
        }

        private static string BuildClashVergeJsSnippet()
        {
            return string.Join("\r\n", new[]
            {
                "  " + JsBlockBegin,
                "  if (config && typeof config === 'object') {",
                "    config['use-system-hosts'] = true;",
                "    if (!config['rule-providers'] || typeof config['rule-providers'] !== 'object') {",
                "      config['rule-providers'] = {};",
                "    }",
                "    config['rule-providers']['didixk-adobe-block'] = {",
                "      type: 'file',",
                "      behavior: 'classical',",
                "      path: './rules/" + ClashProviderFileName + "'",
                "    };",
                "    if (!Array.isArray(config.rules)) {",
                "      config.rules = [];",
                "    }",
                "    config.rules = config.rules.filter(function (r) {",
                "      return typeof r !== 'string' || r.indexOf('RULE-SET,didixk-adobe-block,') !== 0;",
                "    });",
                "    config.rules.unshift('RULE-SET,didixk-adobe-block,REJECT');",
                "  }",
                "  " + JsBlockEnd
            });
        }

        private static string RemoveJsManagedBlock(string scriptText)
        {
            List<string> lines = new List<string>();
            bool skipping = false;
            foreach (string raw in scriptText.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None))
            {
                string trim = raw.Trim();
                if (trim == JsBlockBegin)
                {
                    skipping = true;
                    continue;
                }
                if (skipping)
                {
                    if (trim == JsBlockEnd) skipping = false;
                    continue;
                }
                lines.Add(raw);
            }
            return string.Join("\r\n", lines.ToArray());
        }

        private static bool InjectClashVergeGlobalScript(string vergeDir, UTF8Encoding utf8NoBom)
        {
            string profilesDir = Path.Combine(vergeDir, "profiles");
            Directory.CreateDirectory(profilesDir);

            string scriptPath = Path.Combine(profilesDir, "Script.js");
            string snippet = BuildClashVergeJsSnippet();

            if (!File.Exists(scriptPath))
            {
                string newScript = string.Join("\r\n", new[]
                {
                    "// Clash Verge Rev 全局扩展脚本 | Author: @空影メイオウ SORAKAGEMEIOU",
                    "function main(config, profileName) {",
                    snippet,
                    "  return config;",
                    "}",
                    ""
                });
                File.WriteAllText(scriptPath, newScript, utf8NoBom);
            }
            else
            {
                string existing = File.ReadAllText(scriptPath, Encoding.UTF8);
                string backup = scriptPath + ".didixk-backup";
                if (!File.Exists(backup))
                {
                    File.WriteAllText(backup, existing, utf8NoBom);
                }

                string cleaned = RemoveJsManagedBlock(existing);
                Match retMatch = Regex.Match(cleaned, @"^[ \t]*return\s+config\s*;?", RegexOptions.Multiline);
                string updated;
                if (retMatch.Success)
                {
                    updated = cleaned.Insert(retMatch.Index, snippet + "\r\n");
                }
                else
                {
                    updated = cleaned.TrimEnd() + "\r\n\r\nfunction main(config, profileName) {\r\n" + snippet + "\r\n  return config;\r\n}\r\n";
                }
                File.WriteAllText(scriptPath, updated, utf8NoBom);
            }

            string profilesYamlPath = Path.Combine(vergeDir, "profiles.yaml");
            if (File.Exists(profilesYamlPath))
            {
                string pYaml = File.ReadAllText(profilesYamlPath, Encoding.UTF8);
                if (pYaml.IndexOf("file: Script.js", StringComparison.OrdinalIgnoreCase) < 0 &&
                    pYaml.IndexOf("items:", StringComparison.Ordinal) >= 0)
                {
                    string backup = profilesYamlPath + ".didixk-backup";
                    if (!File.Exists(backup))
                    {
                        File.WriteAllText(backup, pYaml, utf8NoBom);
                    }

                    long ts = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                    string itemEntry = string.Join("\r\n", new[]
                    {
                        "  - uid: Script",
                        "    type: script",
                        "    name: null",
                        "    file: Script.js",
                        "    updated: " + ts
                    });
                    pYaml = Regex.Replace(pYaml, @"^items:\s*\r?\n", "items:\r\n" + itemEntry + "\r\n", RegexOptions.Multiline);
                    File.WriteAllText(profilesYamlPath, pYaml, utf8NoBom);
                }
            }

            string vergeCfgPath = Path.Combine(vergeDir, "clash-verge.yaml");
            if (File.Exists(vergeCfgPath))
            {
                string vYaml = File.ReadAllText(vergeCfgPath, Encoding.UTF8);
                if (Regex.IsMatch(vYaml, @"^use_script:\s*false\s*$", RegexOptions.Multiline))
                {
                    vYaml = Regex.Replace(vYaml, @"^use_script:\s*false\s*$", "use_script: true", RegexOptions.Multiline);
                    File.WriteAllText(vergeCfgPath, vYaml, utf8NoBom);
                }
            }

            return true;
        }

        private static bool InjectMihomoPartyOverride(string partyDir, string overrideYaml, UTF8Encoding utf8NoBom)
        {
            string overrideDir = Path.Combine(partyDir, "override");
            Directory.CreateDirectory(overrideDir);

            string overrideFilePath = Path.Combine(overrideDir, MihomoOverrideId + ".yaml");
            File.WriteAllText(overrideFilePath, overrideYaml, utf8NoBom);

            long ts = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds;
            string profileYamlPath = Path.Combine(overrideDir, "profile.yaml");
            if (!File.Exists(profileYamlPath))
            {
                string newProfileYaml = string.Join("\r\n", new[]
                {
                    "items:",
                    "  - id: " + MihomoOverrideId,
                    "    name: AdobeHostsManager",
                    "    type: local",
                    "    ext: yaml",
                    "    global: true",
                    "    updated: " + ts,
                    ""
                });
                File.WriteAllText(profileYamlPath, newProfileYaml, utf8NoBom);
            }
            else
            {
                string pYaml = File.ReadAllText(profileYamlPath, Encoding.UTF8);
                if (pYaml.IndexOf("id: " + MihomoOverrideId, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    string entry = string.Join("\r\n", new[]
                    {
                        "  - id: " + MihomoOverrideId,
                        "    name: AdobeHostsManager",
                        "    type: local",
                        "    ext: yaml",
                        "    global: true",
                        "    updated: " + ts
                    });
                    if (Regex.IsMatch(pYaml, @"^items:\s*\[\s*\]\s*$", RegexOptions.Multiline))
                    {
                        pYaml = Regex.Replace(pYaml, @"^items:\s*\[\s*\]\s*$", "items:\r\n" + entry, RegexOptions.Multiline);
                    }
                    else if (Regex.IsMatch(pYaml, @"^items:\s*$", RegexOptions.Multiline))
                    {
                        pYaml = Regex.Replace(pYaml, @"^items:\s*$", "items:\r\n" + entry, RegexOptions.Multiline);
                    }
                    else
                    {
                        pYaml = pYaml.TrimEnd() + "\r\nitems:\r\n" + entry + "\r\n";
                    }
                    File.WriteAllText(profileYamlPath, pYaml, utf8NoBom);
                }
            }

            string configYamlPath = Path.Combine(partyDir, "config.yaml");
            if (File.Exists(configYamlPath))
            {
                string cYaml = File.ReadAllText(configYamlPath, Encoding.UTF8);
                if (cYaml.IndexOf(MihomoOverrideId, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    string backup = configYamlPath + ".didixk-backup";
                    if (!File.Exists(backup))
                    {
                        File.WriteAllText(backup, cYaml, utf8NoBom);
                    }

                    if (Regex.IsMatch(cYaml, @"^override:\s*\[\s*\]\s*$", RegexOptions.Multiline))
                    {
                        cYaml = Regex.Replace(cYaml, @"^override:\s*\[\s*\]\s*$", "override:\r\n  - " + MihomoOverrideId, RegexOptions.Multiline);
                        File.WriteAllText(configYamlPath, cYaml, utf8NoBom);
                    }
                    else if (Regex.IsMatch(cYaml, @"^override:\s*$", RegexOptions.Multiline))
                    {
                        cYaml = Regex.Replace(cYaml, @"^override:\s*$", "override:\r\n  - " + MihomoOverrideId, RegexOptions.Multiline);
                        File.WriteAllText(configYamlPath, cYaml, utf8NoBom);
                    }
                }
            }

            return true;
        }

        private static string WriteClashProxyRules(RuleList list, string[] clashDirs)
        {
            Directory.CreateDirectory(ProxyOutputDir);
            UTF8Encoding utf8NoBom = new UTF8Encoding(false);

            string providerText = BuildClashProviderContent(list);
            string mihomoOverrideYaml = BuildMihomoPlusOverrideYaml();

            File.WriteAllText(Path.Combine(ProxyOutputDir, ClashProviderFileName), providerText, utf8NoBom);
            File.WriteAllText(Path.Combine(ProxyOutputDir, "AdobeBlock_Mihomo_Override.yaml"), mihomoOverrideYaml, utf8NoBom);

            int deployedCount = 0;
            List<string> injectedClients = new List<string>();

            foreach (string dir in clashDirs)
            {
                try
                {
                    string rulesDir = Path.Combine(dir, "rules");
                    Directory.CreateDirectory(rulesDir);
                    File.WriteAllText(Path.Combine(rulesDir, ClashProviderFileName), providerText, utf8NoBom);
                    deployedCount++;

                    string lowerDir = dir.ToLowerInvariant();
                    if (lowerDir.Contains("clash-verge-rev"))
                    {
                        if (InjectClashVergeGlobalScript(dir, utf8NoBom))
                        {
                            injectedClients.Add("Clash Verge Rev");
                        }
                    }
                    else if (lowerDir.Contains("mihomo-party") || lowerDir.Contains("clash-party"))
                    {
                        if (InjectMihomoPartyOverride(dir, mihomoOverrideYaml, utf8NoBom))
                        {
                            injectedClients.Add("Mihomo Party");
                        }
                    }
                    else if (lowerDir.Contains("nyanpasu"))
                    {
                        string mergeDir = Path.Combine(dir, "profiles");
                        Directory.CreateDirectory(mergeDir);
                        File.WriteAllText(Path.Combine(mergeDir, "AdobeBlock_Mihomo_Override.yaml"), mihomoOverrideYaml, utf8NoBom);
                    }
                }
                catch { }
            }

            if (injectedClients.Count > 0)
            {
                return string.Format("Clash 规则已自动注入 {0}（重载订阅/配置即生效）", string.Join(" / ", injectedClients.ToArray()));
            }
            if (deployedCount > 0)
            {
                return string.Format("Clash 规则集已部署至 {0} 个客户端目录（配置模板位于 {1}）", deployedCount, ProxyOutputDir);
            }
            return "Clash 规则已生成至 AppData（" + ProxyOutputDir + "）";
        }

        private static void UpdateV2RayJsonConfig(string configPath, RuleList list, bool removeOnly)
        {
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException("找不到指定的 V2Ray/Xray 配置文件：" + configPath);
            }

            UTF8Encoding utf8NoBom = new UTF8Encoding(false);
            string rawJson = File.ReadAllText(configPath, Encoding.UTF8);
            string backup = configPath + ".didixk-backup";
            if (!File.Exists(backup))
            {
                File.WriteAllText(backup, rawJson, utf8NoBom);
            }

            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            Dictionary<string, object> cfg = serializer.Deserialize<Dictionary<string, object>>(rawJson);
            if (cfg == null) cfg = new Dictionary<string, object>();

            Dictionary<string, object> routing;
            if (!cfg.ContainsKey("routing") || !(cfg["routing"] is Dictionary<string, object>))
            {
                routing = new Dictionary<string, object>();
                cfg["routing"] = routing;
            }
            else
            {
                routing = (Dictionary<string, object>)cfg["routing"];
            }

            ArrayList existingRules = null;
            if (routing.ContainsKey("rules") && routing["rules"] is ArrayList)
            {
                existingRules = (ArrayList)routing["rules"];
            }

            List<object> filtered = new List<object>();
            if (existingRules != null)
            {
                foreach (object item in existingRules)
                {
                    Dictionary<string, object> ruleDict = item as Dictionary<string, object>;
                    if (ruleDict != null && ruleDict.ContainsKey("ruleTag") &&
                        string.Equals(Convert.ToString(ruleDict["ruleTag"]), V2RayRuleTag, StringComparison.Ordinal))
                    {
                        continue;
                    }
                    filtered.Add(item);
                }
            }

            if (!removeOnly)
            {
                string[] fullDomains = new string[list.Domains.Length];
                for (int i = 0; i < list.Domains.Length; i++)
                {
                    fullDomains[i] = "full:" + list.Domains[i];
                }

                Dictionary<string, object> blockRule = new Dictionary<string, object>
                {
                    { "type", "field" },
                    { "ruleTag", V2RayRuleTag },
                    { "domain", fullDomains },
                    { "outboundTag", "block" }
                };
                filtered.Insert(0, blockRule);
            }

            routing["rules"] = filtered;
            string prettyJson = FormatJson(serializer.Serialize(cfg));
            File.WriteAllText(configPath, prettyJson + "\r\n", utf8NoBom);
        }

        private static bool InjectV2RayNGuiConfig(string v2rayNDir, RuleList list, bool removeOnly, UTF8Encoding utf8NoBom)
        {
            string guiConfigPath = Path.Combine(Path.Combine(v2rayNDir, "guiConfigs"), "guiNConfig.json");
            if (!File.Exists(guiConfigPath)) return false;

            try
            {
                string rawJson = File.ReadAllText(guiConfigPath, Encoding.UTF8);
                string backup = guiConfigPath + ".didixk-backup";
                if (!File.Exists(backup))
                {
                    File.WriteAllText(backup, rawJson, utf8NoBom);
                }

                JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                Dictionary<string, object> cfg = serializer.Deserialize<Dictionary<string, object>>(rawJson);
                if (cfg == null) return false;

                ArrayList routings = cfg.ContainsKey("routings") ? cfg["routings"] as ArrayList : null;
                if (routings == null)
                {
                    routings = new ArrayList();
                    cfg["routings"] = routings;
                }

                bool modified = false;
                for (int i = 0; i < routings.Count; i++)
                {
                    Dictionary<string, object> rItem = routings[i] as Dictionary<string, object>;
                    if (rItem == null) continue;

                    string remarks = rItem.ContainsKey("remarks") ? Convert.ToString(rItem["remarks"]) : "";
                    ArrayList ruleSet = rItem.ContainsKey("ruleSet") ? rItem["ruleSet"] as ArrayList : null;
                    if (ruleSet == null) continue;

                    List<object> cleanedRules = new List<object>();
                    foreach (object rObj in ruleSet)
                    {
                        Dictionary<string, object> rDict = rObj as Dictionary<string, object>;
                        if (rDict != null && rDict.ContainsKey("ruleTag") &&
                            string.Equals(Convert.ToString(rDict["ruleTag"]), V2RayRuleTag, StringComparison.Ordinal))
                        {
                            modified = true;
                            continue;
                        }
                        cleanedRules.Add(rObj);
                    }

                    if (!removeOnly && (i == 0 || remarks.IndexOf("默认", StringComparison.Ordinal) >= 0 ||
                                        remarks.IndexOf("Default", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        string[] fullDomains = new string[list.Domains.Length];
                        for (int j = 0; j < list.Domains.Length; j++)
                        {
                            fullDomains[j] = "full:" + list.Domains[j];
                        }

                        Dictionary<string, object> blockRule = new Dictionary<string, object>
                        {
                            { "id", "" },
                            { "type", "field" },
                            { "port", "" },
                            { "inboundTag", new string[0] },
                            { "outboundTag", "block" },
                            { "ip", new string[0] },
                            { "domain", fullDomains },
                            { "protocol", new string[0] },
                            { "enabled", true },
                            { "ruleTag", V2RayRuleTag }
                        };
                        cleanedRules.Insert(0, blockRule);
                        modified = true;
                    }

                    rItem["ruleSet"] = cleanedRules;
                }

                if (modified)
                {
                    string prettyJson = FormatJson(serializer.Serialize(cfg));
                    File.WriteAllText(guiConfigPath, prettyJson + "\r\n", utf8NoBom);
                }
                return modified;
            }
            catch
            {
                return false;
            }
        }

        private static string WriteV2RayProxyRules(RuleList list, string[] v2rayNDirs)
        {
            Directory.CreateDirectory(ProxyOutputDir);
            UTF8Encoding utf8NoBom = new UTF8Encoding(false);

            string[] fullDomains = new string[list.Domains.Length];
            for (int i = 0; i < list.Domains.Length; i++)
            {
                fullDomains[i] = "full:" + list.Domains[i];
            }

            Dictionary<string, object> ruleObj = new Dictionary<string, object>
            {
                { "type", "field" },
                { "ruleTag", V2RayRuleTag },
                { "domain", fullDomains },
                { "outboundTag", "block" }
            };

            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            string routingJson = FormatJson(serializer.Serialize(ruleObj));
            File.WriteAllText(Path.Combine(ProxyOutputDir, "AdobeBlock_V2Ray_Routing.json"), routingJson + "\r\n", utf8NoBom);
            File.WriteAllText(Path.Combine(ProxyOutputDir, "AdobeBlock_v2rayN_Domains.txt"), string.Join("\r\n", fullDomains) + "\r\n", utf8NoBom);

            List<string> notes = new List<string>();
            if (!string.IsNullOrWhiteSpace(_opts.ProxyConfigPath))
            {
                UpdateV2RayJsonConfig(_opts.ProxyConfigPath, list, false);
                notes.Add("已自动写入 " + _opts.ProxyConfigPath);
            }

            foreach (string vDir in v2rayNDirs)
            {
                if (InjectV2RayNGuiConfig(vDir, list, false, utf8NoBom))
                {
                    notes.Add("已自动注入 v2rayN 路由规则");
                }
                string binConfig = Path.Combine(Path.Combine(vDir, "binConfigs"), "config.json");
                if (File.Exists(binConfig))
                {
                    try { UpdateV2RayJsonConfig(binConfig, list, false); } catch { }
                }
            }

            if (notes.Count > 0)
            {
                return string.Format("V2Ray/v2rayN 规则已生成至 AppData（{0}）", string.Join("，", notes.ToArray()));
            }
            return "V2Ray/v2rayN 规则已生成至 AppData（" + ProxyOutputDir + "）";
        }

        private static string SyncProxyRules(RuleList list, bool removeOnly)
        {
            if (string.Equals(_opts.ProxyMode, "None", StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrWhiteSpace(_opts.ProxyConfigPath))
            {
                return "";
            }

            UTF8Encoding utf8NoBom = new UTF8Encoding(false);

            if (removeOnly)
            {
                List<string> notes = new List<string>();
                foreach (string dir in GetDetectedClashDirs())
                {
                    try
                    {
                        string f = Path.Combine(Path.Combine(dir, "rules"), ClashProviderFileName);
                        if (File.Exists(f)) File.Delete(f);

                        string scriptPath = Path.Combine(Path.Combine(dir, "profiles"), "Script.js");
                        if (File.Exists(scriptPath))
                        {
                            string cleaned = RemoveJsManagedBlock(File.ReadAllText(scriptPath, Encoding.UTF8));
                            File.WriteAllText(scriptPath, cleaned, utf8NoBom);
                        }

                        string mihomoOvr = Path.Combine(Path.Combine(dir, "override"), MihomoOverrideId + ".yaml");
                        if (File.Exists(mihomoOvr)) File.Delete(mihomoOvr);
                    }
                    catch { }
                }

                foreach (string vDir in GetDetectedV2RayNDirs())
                {
                    InjectV2RayNGuiConfig(vDir, null, true, utf8NoBom);
                    string binConfig = Path.Combine(Path.Combine(vDir, "binConfigs"), "config.json");
                    if (File.Exists(binConfig))
                    {
                        try { UpdateV2RayJsonConfig(binConfig, null, true); } catch { }
                    }
                }

                if (Directory.Exists(ProxyOutputDir))
                {
                    try
                    {
                        Directory.Delete(ProxyOutputDir, true);
                        notes.Add("已清理 AppData 代理规则与注入配置");
                    }
                    catch { }
                }

                if (!string.IsNullOrWhiteSpace(_opts.ProxyConfigPath) && File.Exists(_opts.ProxyConfigPath))
                {
                    UpdateV2RayJsonConfig(_opts.ProxyConfigPath, null, true);
                    notes.Add("已从 " + _opts.ProxyConfigPath + " 移除拦截规则");
                }
                return string.Join("；", notes.ToArray());
            }

            ProxyPresence detected = TestProxyClientPresence();
            bool isAuto = string.Equals(_opts.ProxyMode, "Auto", StringComparison.OrdinalIgnoreCase);
            bool isAll = string.Equals(_opts.ProxyMode, "All", StringComparison.OrdinalIgnoreCase);

            bool doClash = string.Equals(_opts.ProxyMode, "Clash", StringComparison.OrdinalIgnoreCase) || isAll || (isAuto && detected.HasClash);
            bool doV2Ray = string.Equals(_opts.ProxyMode, "V2Ray", StringComparison.OrdinalIgnoreCase) || isAll || (isAuto && detected.HasV2Ray) ||
                           !string.IsNullOrWhiteSpace(_opts.ProxyConfigPath);

            List<string> summaries = new List<string>();
            if (doClash) summaries.Add(WriteClashProxyRules(list, detected.ClashDirs));
            if (doV2Ray) summaries.Add(WriteV2RayProxyRules(list, detected.V2RayNDirs));

            return string.Join("；", summaries.ToArray());
        }

        private static string FormatJson(string json)
        {
            StringBuilder sb = new StringBuilder(json.Length * 2);
            int indent = 0;
            bool inString = false;
            bool escaped = false;

            for (int i = 0; i < json.Length; i++)
            {
                char ch = json[i];
                if (inString)
                {
                    sb.Append(ch);
                    if (escaped) escaped = false;
                    else if (ch == '\\') escaped = true;
                    else if (ch == '"') inString = false;
                    continue;
                }

                switch (ch)
                {
                    case '"':
                        inString = true;
                        sb.Append(ch);
                        break;
                    case '{':
                    case '[':
                        sb.Append(ch);
                        if (i + 1 < json.Length && (json[i + 1] == '}' || json[i + 1] == ']'))
                        {
                            sb.Append(json[++i]);
                        }
                        else
                        {
                            indent++;
                            sb.Append("\r\n").Append(' ', indent * 2);
                        }
                        break;
                    case '}':
                    case ']':
                        indent = Math.Max(0, indent - 1);
                        sb.Append("\r\n").Append(' ', indent * 2).Append(ch);
                        break;
                    case ',':
                        sb.Append(ch).Append("\r\n").Append(' ', indent * 2);
                        break;
                    case ':':
                        sb.Append(": ");
                        break;
                    default:
                        if (!char.IsWhiteSpace(ch)) sb.Append(ch);
                        break;
                }
            }
            return sb.ToString();
        }

        // ==================== 仅出错时显示的诊断与手动指南 ====================
        private static void ShowTroubleshootingGuide(Exception ex, RuleList resolvedList, string sourceLabel)
        {
            Console.WriteLine();
            WriteColoredLine("====================================================================", ConsoleColor.Red);
            WriteColoredLine("  AdobeHostsManager — 执行失败与排查指南", ConsoleColor.Red);
            WriteColoredLine("  作者：@空影メイオウ SORAKAGEMEIOU", ConsoleColor.Gray);
            WriteColoredLine("====================================================================", ConsoleColor.Red);
            WriteColoredLine("错误原因：" + ex.Message, ConsoleColor.Red);
            WriteColoredLine("异常类型：" + ex.GetType().Name, ConsoleColor.DarkYellow);
            Console.WriteLine();

            WriteColoredLine("【常见失败原因与解决方法】", ConsoleColor.Yellow);
            WriteColoredLine("  1. 杀毒软件 / 安全防护拦截 hosts 或防火墙修改（最常见）", ConsoleColor.White);
            Console.WriteLine("     火绒、360、Windows Defender、腾讯电脑管家、卡巴斯基等常锁定 hosts 或接管防火墙。");
            Console.WriteLine("     请先暂时关闭防护，完成后再开启；或加参数 -FirewallMode Skip 仅修改 hosts。");
            WriteColoredLine("  2. 权限不足或域控限制", ConsoleColor.White);
            Console.WriteLine("     UAC 弹窗点击了「否」或当前非管理员账户，请右键选择「以管理员身份运行」。");
            WriteColoredLine("  3. hosts 文件属性被锁定或 NTFS 权限异常", ConsoleColor.White);
            Console.WriteLine("     在管理员 CMD/PowerShell 中依次运行以下命令后重试：");
            WriteColoredLine(@"       attrib -r -s -h C:\Windows\System32\drivers\etc\hosts", ConsoleColor.Cyan);
            WriteColoredLine(@"       icacls C:\Windows\System32\drivers\etc\hosts /grant Administrators:F", ConsoleColor.Cyan);
            WriteColoredLine("  4. hosts 正被其他程序占用", ConsoleColor.White);
            Console.WriteLine("     请关闭记事本、VS Code、SwitchHosts、Watt Toolkit (Steam++) 或代理软件后重试。");
            WriteColoredLine("  5. GitHub / 规则源无法访问且本地缺少离线文件", ConsoleColor.White);
            Console.WriteLine("     程序已内置 Fastly / Gcore / jsDelivr 多路 CDN 镜像；若仍全部不通：");
            Console.WriteLine("     - 确认 AppData 或同目录存在 AdobeHosts_Offline.txt，再加 -OfflineOnly 运行；");
            Console.WriteLine("     - 若有本地代理，可带参数运行：AdobeHostsManager.exe -Proxy \"http://127.0.0.1:7890\"");
            WriteColoredLine("  6. 使用 Clash / V2Ray 代理时 hosts 不生效", ConsoleColor.White);
            Console.WriteLine("     程序已自动向 Clash Verge Rev / Mihomo Party / v2rayN 注入拦截规则；");
            Console.WriteLine("     若正在运行代理客户端，请在客户端中点击「重新加载/刷新订阅」使新规则立即生效。");
            WriteColoredLine("  7. 旧规则区块标记不完整", ConsoleColor.White);
            Console.WriteLine("     若曾手动删坏 hosts 末尾标记，请用备份 hosts.didixk-backup 恢复。");
            Console.WriteLine();

            bool exported = ExportManualRuleFile(resolvedList, sourceLabel);

            WriteColoredLine("【手动修改 hosts 步骤】", ConsoleColor.Cyan);
            if (string.Equals(_opts.Action, "Remove", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(@"  1. 打开目录 C:\Windows\System32\drivers\etc，先备份 hosts 文件。");
                Console.WriteLine(string.Format("  2. 将 hosts 复制到桌面用记事本打开，删除「{0}」到「{1}」之间的内容并保存。", BlockBegin, BlockEnd));
                Console.WriteLine("  3. 将桌面 hosts 复制回原目录覆盖（或直接用 hosts.didixk-backup 改名覆盖）。");
                Console.WriteLine("  4. 管理员 CMD 执行 ipconfig /flushdns（或重启电脑）。");
            }
            else
            {
                if (exported)
                {
                    WriteColoredLine("  1. 已导出可直接粘贴的规则文件：" + ManualExportFile, ConsoleColor.Green);
                }
                else if (File.Exists(OfflineListFile))
                {
                    Console.WriteLine("  1. 打开离线规则文件：" + OfflineListFile + " 并全选复制。");
                }
                else
                {
                    Console.WriteLine("  1. 从镜像链接下载并复制全部规则内容。");
                }
                Console.WriteLine(@"  2. 打开 C:\Windows\System32\drivers\etc，先复制一份 hosts 留作备份。");
                Console.WriteLine("  3. 将 hosts 复制到桌面用记事本打开，把规则粘贴到文件末尾并保存（确保无 .txt 后缀）。");
                Console.WriteLine(@"  4. 将修改后的 hosts 复制回 C:\Windows\System32\drivers\etc 覆盖（杀毒弹窗请点允许）。");
                Console.WriteLine("  5. 按 Win+R 输入 cmd 执行 ipconfig /flushdns（或重启电脑）生效。");
            }
            WriteColoredLine("====================================================================", ConsoleColor.Cyan);
        }

        private static void WriteColoredLine(string text, ConsoleColor color)
        {
            ConsoleColor prev = Console.ForegroundColor;
            try
            {
                Console.ForegroundColor = color;
                Console.WriteLine(text);
            }
            finally
            {
                Console.ForegroundColor = prev;
            }
        }
    }
}
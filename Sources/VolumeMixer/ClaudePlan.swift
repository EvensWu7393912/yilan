import Foundation
import Security

struct PlanLimit {
    let key: String
    let name: String
    let percent: Double // 0...100
    let resetsAt: Date?
}

enum PlanStatus {
    case ok(limits: [PlanLimit], plan: String?)
    case noLogin
    case expired
    case rateLimited(TimeInterval)
    case failed(String)
}

/// Claude subscription limits (the numbers `/usage` shows), fetched with Claude Code's own login.
/// The token is never refreshed here: refresh tokens are single-use, so doing it ourselves would sign
/// Claude Code out. When it expires, the `claude` CLI is asked to refresh it instead.
enum ClaudePlanClient {
    private static let endpoint = URL(string: "https://api.anthropic.com/api/oauth/usage")!

    private static var lastCLIRefresh: Date?

    /// Only called from AIUsage's single in-flight plan task.
    static func fetch() async -> PlanStatus {
        guard var credentials = await loadCredentials() else { return .noLogin }
        if let expiry = credentials.expiresAt, expiry <= Date() {
            guard let fresh = await refreshedByCLI(replacing: credentials) else { return .expired }
            credentials = fresh
        }
        let status = await request(credentials)
        if case .expired = status, let fresh = await refreshedByCLI(replacing: credentials) {
            return await request(fresh)
        }
        return status
    }

    private static func loadCredentials() async -> Credentials? {
        await Task.detached(priority: .utility, operation: readCredentials).value
    }

    /// Runs a harmless CLI command, which makes Claude Code refresh and store its own token.
    /// At most every 15 minutes, so a dead login doesn't spawn a process on every poll.
    private static func refreshedByCLI(replacing old: Credentials) async -> Credentials? {
        if let last = lastCLIRefresh, Date().timeIntervalSince(last) < 900 { return nil }
        lastCLIRefresh = Date()
        await runClaudeAuthStatus()
        guard let fresh = await loadCredentials(), fresh.token != old.token else { return nil }
        return fresh
    }

    private static func runClaudeAuthStatus() async {
        await withCheckedContinuation { (done: CheckedContinuation<Void, Never>) in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/zsh")
            process.arguments = ["-lc", """
                export PATH="$HOME/.local/bin:$HOME/.claude/local:$HOME/.bun/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
                claude auth status
                """]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            process.terminationHandler = { _ in done.resume() }
            do {
                try process.run()
            } catch {
                done.resume()
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
                if process.isRunning { process.terminate() }
            }
        }
    }

    private static func request(_ credentials: Credentials) async -> PlanStatus {
        var request = URLRequest(url: endpoint, timeoutInterval: 15)
        request.setValue("Bearer \(credentials.token)", forHTTPHeaderField: "Authorization")
        request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        request.setValue("VolumeMixer/1.0", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status == 401 { return .expired }
            if status == 429 {
                let retry = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Retry-After").flatMap { TimeInterval($0) }
                return .rateLimited(max(retry ?? 600, 60))
            }
            guard status == 200, let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return .failed("HTTP \(status)")
            }
            let limits = parse(json)
            // An empty list would look like "no usage"; say the format changed instead.
            return limits.isEmpty ? .failed("响应中没有限额数据") : .ok(limits: limits, plan: credentials.plan)
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// Every top-level object with a `utilization` field is a limit window
    /// (five_hour, seven_day, seven_day_opus, ...), so new windows show up without code changes.
    /// A `limits` array is read too: the endpoint is private and newer responses may use one.
    private static func parse(_ json: [String: Any]) -> [PlanLimit] {
        let order = ["five_hour", "seven_day", "seven_day_opus", "seven_day_sonnet"]
        var windows = json.compactMapValues { $0 as? [String: Any] }
        for entry in json["limits"] as? [[String: Any]] ?? [] {
            if let key = ["kind", "type", "id", "name"].lazy.compactMap({ entry[$0] as? String }).first {
                windows[key == "session" ? "five_hour" : key] = entry
            }
        }
        return windows.compactMap { key, w -> PlanLimit? in
            guard let used = ["utilization", "used_percent", "percent_used"].lazy
                .compactMap({ (w[$0] as? NSNumber)?.doubleValue }).first else { return nil }
            return PlanLimit(key: key, name: name(for: key), percent: used,
                             resetsAt: ((w["resets_at"] ?? w["reset_at"]) as? String).flatMap(parseDate))
        }
        .sorted { (order.firstIndex(of: $0.key) ?? 99, $0.key) < (order.firstIndex(of: $1.key) ?? 99, $1.key) }
    }

    private static func name(for key: String) -> String {
        switch key {
        case "five_hour": return "5 小时限额"
        case "seven_day": return "每周限额"
        case "seven_day_opus": return "每周 Opus"
        case "seven_day_sonnet": return "每周 Sonnet"
        default: return key.replacingOccurrences(of: "_", with: " ")
        }
    }

    private static func parseDate(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    private struct Credentials: Sendable {
        let token: String
        let expiresAt: Date?
        let plan: String?
    }

    /// Blocks while macOS asks the user to allow access, so it runs off the main thread.
    /// Claude Code rewrites this item on every refresh, which resets the apps trusted to read it.
    /// It uses `security` itself, so reading the same way avoids a Keychain prompt each time.
    @Sendable private static func readCredentials() -> Credentials? {
        if let data = readWithSecurityTool(), let credentials = parse(credentials: data) { return credentials }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Claude Code-credentials",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return parse(credentials: data)
    }

    private static func readWithSecurityTool() -> Data? {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["find-generic-password", "-s", "Claude Code-credentials", "-w"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return process.terminationStatus == 0 ? data : nil
    }

    private static func parse(credentials data: Data) -> Credentials? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let oauth = json["claudeAiOauth"] as? [String: Any],
              let token = oauth["accessToken"] as? String else { return nil }
        let expiry = (oauth["expiresAt"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue / 1000) }
        return Credentials(token: token, expiresAt: expiry, plan: oauth["subscriptionType"] as? String)
    }
}

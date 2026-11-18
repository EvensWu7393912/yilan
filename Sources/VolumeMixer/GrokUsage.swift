import AppKit
import CryptoKit
import Foundation
import Security

struct GrokUsage {
    let percent: Double?
    let available: Bool?
    let resetsAt: Date?
    let plan: String?
    let onDemandCents: Double?
    let onDemandLimitCents: Double?
}

enum GrokStatus {
    case ok(GrokUsage)
    case notLinked
    case expired
    case failed(String)
}

/// Grok Bot's weekly pool has no public API. This uses the private dashboard endpoints the app itself
/// talks to, so it can break without notice. It signs in with its own browser login and keeps its own
/// token pair in the Keychain, so refreshing never touches the Grok Bot app's session.
enum GrokClient {
    private static let backend = URL(string: "https://api2.cursor.sh")!
    private static let clientID = "KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB"
    private static let keychainService = "一览.grok"

    private struct Tokens: Codable, Sendable {
        var access: String
        var refresh: String?
    }

    private enum CallResult {
        case ok([String: Any])
        case unauthorized
        case failed(String)
    }

    // MARK: Usage

    static func fetch() async -> GrokStatus {
        guard var tokens = await Task.detached(priority: .utility, operation: loadTokens).value else { return .notLinked }

        if let expiry = expiry(of: tokens.access), expiry.timeIntervalSinceNow < 300, tokens.refresh != nil {
            if let fresh = await refreshed(tokens) { tokens = fresh } else if expiry <= Date() { return .expired }
        }

        var status = await call("GetSandUsageStatus", token: tokens.access)
        if case .unauthorized = status {
            guard let fresh = await refreshed(tokens) else { return .expired }
            tokens = fresh
            status = await call("GetSandUsageStatus", token: tokens.access)
        }

        switch status {
        case .unauthorized: return .expired
        case .failed(let reason): return .failed(reason)
        case .ok(let sand):
            // Spend is a bonus: a failure here must not hide the weekly percentage.
            var spend: [String: Any]?
            if case .ok(let period) = await call("GetCurrentPeriodUsage", token: tokens.access) {
                spend = period["spendLimitUsage"] as? [String: Any]
            }
            return .ok(GrokUsage(percent: number(sand["usagePercent"]),
                                 available: sand["hasAvailableUsage"] as? Bool,
                                 resetsAt: date(sand["nextResetTimestampUtc"]),
                                 plan: sand["grokPlanLabel"] as? String,
                                 onDemandCents: number(spend?["individualUsed"]) ?? number(spend?["totalSpend"]),
                                 onDemandLimitCents: number(spend?["individualLimit"])))
        }
    }

    private static func call(_ method: String, token: String) async -> CallResult {
        var request = URLRequest(url: backend.appendingPathComponent("aiserver.v1.DashboardService/\(method)"),
                                 timeoutInterval: 15)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(checksum(), forHTTPHeaderField: "x-cursor-checksum")
        request.setValue("sand", forHTTPHeaderField: "x-cursor-client-type")
        request.setValue("0.1.0", forHTTPHeaderField: "x-cursor-client-version")
        request.setValue("prod", forHTTPHeaderField: "x-sand-box-namespace")
        request.setValue("true", forHTTPHeaderField: "x-ghost-mode")
        request.setValue(UUID().uuidString.lowercased(), forHTTPHeaderField: "x-request-id")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            if code == 401 { return .unauthorized }
            guard code == 200, let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return .failed("HTTP \(code)")
            }
            return .ok(json)
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// The server checks this header. The shifts copy JavaScript, where they wrap at 32 bits: `>> 40` is `>> 8`.
    private static func checksum() -> String {
        let ks = Int32(truncatingIfNeeded: Int64(Date().timeIntervalSince1970 * 1000) / 1_000_000)
        var bytes = [40, 32, 24, 16, 8, 0].map { UInt8(truncatingIfNeeded: ks >> Int32($0 & 31)) }
        var previous: UInt8 = 165
        for i in bytes.indices {
            bytes[i] = (bytes[i] ^ previous) &+ UInt8(i)
            previous = bytes[i]
        }
        return base64URL(Data(bytes)) + UUID().uuidString.lowercased()
    }

    // MARK: Sign-in

    /// Opens the browser sign-in and waits for it to finish. Returns false on timeout.
    static func login() async -> Bool {
        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else { return false }
        let verifier = base64URL(Data(random))
        let challenge = base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
        let id = UUID().uuidString.lowercased()

        var page = URLComponents(string: "https://cursor.com/loginDeepControl")!
        page.queryItems = [.init(name: "challenge", value: challenge), .init(name: "uuid", value: id),
                           .init(name: "mode", value: "login"), .init(name: "redirectTarget", value: "cli")]
        var poll = URLComponents(url: backend.appendingPathComponent("auth/poll"), resolvingAgainstBaseURL: false)!
        poll.queryItems = [.init(name: "uuid", value: id), .init(name: "verifier", value: verifier)]
        guard let pageURL = page.url, let pollURL = poll.url else { return false }
        await MainActor.run { _ = NSWorkspace.shared.open(pageURL) }

        let deadline = Date().addingTimeInterval(300)
        while Date() < deadline {
            try? await Task.sleep(for: .seconds(3))
            guard let (data, response) = try? await URLSession.shared.data(from: pollURL),
                  (response as? HTTPURLResponse)?.statusCode == 200,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let access = json["accessToken"] as? String else { continue }
            let tokens = Tokens(access: access, refresh: json["refreshToken"] as? String)
            return await Task.detached(priority: .utility) { save(tokens) }.value
        }
        return false
    }

    static func unlink() {
        SecItemDelete(baseQuery as CFDictionary)
    }

    private static func refreshed(_ tokens: Tokens) async -> Tokens? {
        guard let refresh = tokens.refresh else { return nil }
        var request = URLRequest(url: backend.appendingPathComponent("oauth/token"), timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: [
            "client_id": clientID, "grant_type": "refresh_token", "refresh_token": refresh,
        ])
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let access = json["access_token"] as? String else { return nil }
        let fresh = Tokens(access: access, refresh: json["refresh_token"] as? String ?? refresh)
        _ = await Task.detached(priority: .utility) { save(fresh) }.value
        return fresh
    }

    // MARK: Keychain

    private static var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: keychainService,
         kSecAttrAccount as String: "default"]
    }

    @Sendable private static func loadTokens() -> Tokens? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(Tokens.self, from: data)
    }

    @discardableResult
    private static func save(_ tokens: Tokens) -> Bool {
        guard let data = try? JSONEncoder().encode(tokens) else { return false }
        SecItemDelete(baseQuery as CFDictionary)
        var query = baseQuery
        query[kSecValueData as String] = data
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    // MARK: Parsing

    private static func expiry(of jwt: String) -> Date? {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var payload = parts[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
        guard let data = Data(base64Encoded: payload),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let exp = number(json["exp"]) else { return nil }
        return Date(timeIntervalSince1970: exp)
    }

    /// Connect JSON sends 64-bit integers as strings.
    private static func number(_ value: Any?) -> Double? {
        if let n = value as? NSNumber { return n.doubleValue }
        if let s = value as? String { return Double(s) }
        return nil
    }

    private static func date(_ value: Any?) -> Date? {
        if let ms = number(value) { return Date(timeIntervalSince1970: ms / 1000) }
        guard let s = value as? String else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

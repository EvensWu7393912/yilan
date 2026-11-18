import AppKit
import Darwin
import SwiftUI

struct TopApp: Identifiable {
    let id: pid_t // the app's main (responsible) process
    let name: String
    let icon: NSImage
    var cpu: Double = 0    // percent of one core, like Activity Monitor (can exceed 100)
    var memory: UInt64 = 0 // physical footprint in bytes
}

/// The apps using the most CPU or memory, for the status page's collapsible board.
/// Helper processes (browser renderers, things started from a terminal) are counted under the app
/// responsible for them. Only this user's processes are visible without root, so system daemons
/// such as WindowServer are not listed. Samples every 2 s, and only while the board is expanded.
@MainActor
final class TopApps: ObservableObject {
    static let count = 5

    @Published private(set) var apps: [TopApp] = []
    @Published private(set) var ready = false // false until there are two samples to diff
    var byMemory = false { didSet { if byMemory != oldValue { publish() } } }

    private var timer: Timer?
    private var lastCPU: [pid_t: UInt64] = [:] // cumulative CPU time per process, ns
    private var lastTime: Date?
    private var owners: [pid_t: (name: String, icon: NSImage)] = [:]
    private var roots: [pid_t: pid_t] = [:]
    private var totals: [pid_t: (cpu: Double, memory: UInt64)] = [:]

    private static let timebase: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(info.numer) / Double(info.denom)
    }()

    func setActive(_ active: Bool) {
        timer?.invalidate()
        timer = nil
        guard active else {
            // Stale deltas would show a bogus spike on the next open.
            lastCPU = [:]
            lastTime = nil
            ready = false
            return
        }
        sample()
        // CPU needs two samples; take the second one early so the board fills in quickly.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
            guard let self, self.timer != nil, !self.ready else { return }
            self.sample()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.sample() }
        }
        timer?.tolerance = 0.2
    }

    private func sample() {
        let now = Date()
        let elapsed = lastTime.map { now.timeIntervalSince($0) } ?? 0
        if lastTime != nil, elapsed < 0.3 { return }

        var pids = [pid_t](repeating: 0, count: Int(proc_listallpids(nil, 0)) + 32)
        let filled = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.stride))
        guard filled > 0 else { return }

        var cpuNow: [pid_t: UInt64] = [:]
        var sums: [pid_t: (cpu: Double, memory: UInt64)] = [:]
        for pid in pids.prefix(Int(filled)) where pid > 0 {
            var usage = rusage_info_v4()
            let ok = withUnsafeMutablePointer(to: &usage) {
                $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
            } == 0
            guard ok else { continue } // another user's process
            let cpu = UInt64(Double(usage.ri_user_time + usage.ri_system_time) * Self.timebase)
            cpuNow[pid] = cpu

            let root = root(of: pid)
            var sum = sums[root] ?? (0, 0)
            sum.memory += usage.ri_phys_footprint
            if elapsed > 0, let before = lastCPU[pid], cpu >= before {
                sum.cpu += Double(cpu - before) / (elapsed * 1_000_000_000) * 100
            }
            sums[root] = sum
        }

        roots = roots.filter { cpuNow[$0.key] != nil }
        owners = owners.filter { sums[$0.key] != nil }
        if lastTime != nil { ready = true }
        lastCPU = cpuNow
        lastTime = now
        totals = sums
        publish()
    }

    private func publish() {
        let ranked = totals.sorted {
            byMemory ? $0.value.memory > $1.value.memory
                     : ($0.value.cpu, $0.value.memory) > ($1.value.cpu, $1.value.memory)
        }
        apps = ranked.prefix(Self.count).map { pid, total in
            let owner = owner(of: pid)
            return TopApp(id: pid, name: owner.name, icon: owner.icon, cpu: total.cpu, memory: total.memory)
        }
    }

    // MARK: Process → app

    private func root(of pid: pid_t) -> pid_t {
        if let cached = roots[pid] { return cached }
        let responsible = responsibility_get_pid_responsible_for_pid(pid)
        let root = responsible > 0 ? responsible : pid
        roots[pid] = root
        return root
    }

    private func owner(of pid: pid_t) -> (name: String, icon: NSImage) {
        if let cached = owners[pid] { return cached }
        var resolved: (name: String, icon: NSImage)
        if let app = NSRunningApplication(processIdentifier: pid), let name = app.localizedName {
            resolved = (name, app.icon ?? NSWorkspace.shared.icon(for: .application))
        } else {
            var buffer = [CChar](repeating: 0, count: 4096)
            let path = proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 ? String(cString: buffer) : nil
            if let path, let range = path.range(of: ".app/") {
                let appPath = String(path[..<range.lowerBound]) + ".app"
                resolved = (FileManager.default.displayName(atPath: appPath).replacingOccurrences(of: ".app", with: ""),
                            NSWorkspace.shared.icon(forFile: appPath))
            } else {
                resolved = (path.map { ($0 as NSString).lastPathComponent } ?? "进程 \(pid)",
                            NSWorkspace.shared.icon(for: .unixExecutable))
            }
        }
        owners[pid] = resolved
        return resolved
    }
}

// MARK: - Board

/// Collapsible "top apps" board on the status page; remembers whether it is open and how it is sorted.
struct TopAppsBoard: View {
    @StateObject private var top = TopApps()
    @AppStorage("statusTopExpanded") private var expanded = true
    @AppStorage("statusTopByMemory") private var byMemory = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Button {
                    expanded.toggle()
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "chevron.right")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(expanded ? 90 : 0))
                        Text("占用最高").font(.headline)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(expanded ? "收起" : "展开")
                Spacer()
                if expanded {
                    Picker("", selection: $byMemory) {
                        Text("CPU").tag(false)
                        Text("内存").tag(true)
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .controlSize(.mini)
                    .fixedSize()
                }
            }
            if expanded {
                if top.apps.isEmpty || (!byMemory && !top.ready) {
                    Text("正在采样…")
                        .font(.caption).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, minHeight: rowHeight * CGFloat(TopApps.count), alignment: .center)
                } else {
                    VStack(spacing: 6) {
                        ForEach(top.apps) { row($0) }
                    }
                }
            }
        }
        .onAppear {
            top.byMemory = byMemory
            top.setActive(expanded)
        }
        .onDisappear { top.setActive(false) }
        .onChange(of: expanded) { _, open in top.setActive(open) }
        .onChange(of: byMemory) { _, memory in top.byMemory = memory }
    }

    private let rowHeight: CGFloat = 22

    private func row(_ app: TopApp) -> some View {
        HStack(spacing: 8) {
            Image(nsImage: app.icon)
                .resizable().interpolation(.high)
                .frame(width: 16, height: 16)
            Text(app.name).lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 4)
            UsageBar(fraction: fraction(app), tint: tint(app))
                .frame(width: 44)
            Text(byMemory ? ByteCountFormatter.string(fromByteCount: Int64(app.memory), countStyle: .memory)
                          : String(format: app.cpu < 99.95 ? "%.1f%%" : "%.0f%%", app.cpu))
                .font(.caption).monospacedDigit().foregroundStyle(.secondary)
                .frame(width: 58, alignment: .trailing)
        }
        .frame(height: 16)
    }

    /// CPU: share of one core. Memory: relative to the largest app listed.
    private func fraction(_ app: TopApp) -> Double {
        if byMemory {
            let peak = top.apps.map(\.memory).max() ?? 0
            return peak == 0 ? 0 : Double(app.memory) / Double(peak)
        }
        return app.cpu / 100
    }

    private func tint(_ app: TopApp) -> Color {
        guard !byMemory else { return .accentColor }
        switch app.cpu {
        case ..<50: return .accentColor
        case ..<100: return .orange
        default: return .red
        }
    }
}

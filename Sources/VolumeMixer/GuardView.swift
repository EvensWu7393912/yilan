import SwiftUI

/// 安全页：异常清单在上，系统防护状态和全部启动项在下。
struct GuardView: View {
    @EnvironmentObject private var guardian: SecurityGuard
    @AppStorage("guardItemsExpanded") private var itemsExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if !guardian.alerts.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(guardian.alerts) { AlertRow(alert: $0) }
                    }
                }
                .frame(maxHeight: 300)
                .fixedSize(horizontal: false, vertical: true)
                if guardian.alerts.contains(where: \.event) {
                    HStack {
                        Spacer()
                        Button("清除所有已处理的记录") { guardian.dismissAllEvents() }
                            .buttonStyle(.link)
                            .font(.caption)
                    }
                }
            }
            Divider()
            postureRow
            if !guardian.historyInstant {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "clock.badge.exclamationmark").foregroundStyle(.orange)
                    Text("终端要关窗口才写历史，粘贴的命令要等那时才查得到。")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("改为即时") { guardian.enableInstantHistory() }
                        .controlSize(.small)
                        .help("在 ~/.zshrc 末尾加 setopt INC_APPEND_HISTORY")
                }
            }
            Divider()
            launchItemsSection
        }
    }

    private var header: some View {
        let critical = guardian.alerts.filter { $0.severity == .critical }.count
        let attention = guardian.alerts.filter { $0.severity >= .warning }.count
        return HStack(spacing: 10) {
            Image(systemName: critical > 0 ? "exclamationmark.shield.fill" : (attention > 0 ? "shield.lefthalf.filled" : "checkmark.shield.fill"))
                .font(.system(size: 26))
                .foregroundStyle(critical > 0 ? .red : (attention > 0 ? .orange : .green))
            VStack(alignment: .leading, spacing: 1) {
                Text(critical > 0 ? "\(critical) 项高危异常" : (attention > 0 ? "\(attention) 项需要确认" : "未发现异常"))
                    .font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }
            Spacer()
            Button {
                guardian.scanAll()
                guardian.refreshPosture()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("立即检查")
        }
    }

    private var subtitle: String {
        var parts: [String] = []
        if let date = guardian.lastScan { parts.append(date.formatted(date: .omitted, time: .standard) + " 检查") }
        parts.append("启动项 \(guardian.launchItems.count)")
        parts.append("进程 \(guardian.processCount)")
        return parts.joined(separator: " · ")
    }

    private var postureRow: some View {
        HStack(spacing: 10) {
            badge("SIP", guardian.posture.sip, help: "系统完整性保护")
            badge("Gatekeeper", guardian.posture.gatekeeper, help: "只允许运行已签名、已公证的程序")
            badge("FileVault", guardian.posture.fileVault, help: "磁盘加密")
            badge("防火墙", guardian.posture.firewall, help: "应用防火墙（入站连接）")
        }
        .font(.caption)
    }

    private func badge(_ name: String, _ on: Bool?, help: String) -> some View {
        HStack(spacing: 2) {
            Image(systemName: on == nil ? "questionmark.circle" : (on! ? "checkmark.circle.fill" : "xmark.circle.fill"))
                .foregroundStyle(on == nil ? .secondary : (on! ? Color.green : Color.orange))
            Text(name).foregroundStyle(.secondary)
        }
        .help(help + (on == nil ? "：未知" : (on! ? "：已开启" : "：已关闭")))
    }

    private var launchItemsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                itemsExpanded.toggle()
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "chevron.right")
                        .font(.caption.bold()).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(itemsExpanded ? 90 : 0))
                    Text("全部启动项").font(.headline)
                    Text("\(guardian.launchItems.count)").foregroundStyle(.secondary)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if itemsExpanded {
                ScrollView {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(guardian.launchItems) { item in
                            LaunchItemRow(item: item)
                        }
                    }
                }
                .frame(maxHeight: 220)
                .fixedSize(horizontal: false, vertical: true)
            }
            Text("启动项目录实时监听 · 进程每 3 秒检查 · 终端命令写入历史后检查")
                .font(.caption2).foregroundStyle(.tertiary)
        }
    }
}

private struct AlertRow: View {
    @EnvironmentObject private var guardian: SecurityGuard
    let alert: SecurityAlert

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: alert.severity == .critical ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(alert.severity == .critical ? .red : .orange)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 3) {
                Text(alert.title).font(.callout.weight(.medium)).lineLimit(2)
                Text(alert.detail)
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(6)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if let path = alert.path ?? alert.executable {
                    Text(path)
                        .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                        .help(path)
                }
                HStack(spacing: 6) { actions }
                    .controlSize(.small)
                    .padding(.top, 1)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 8).fill((alert.severity == .critical ? Color.red : Color.orange).opacity(0.08)))
    }

    @ViewBuilder
    private var actions: some View {
        switch alert.kind {
        case .launchItem:
            Button("停用并隔离") { guardian.disable(alert) }
            Button("显示") { guardian.reveal(alert.path!) }
            Button("信任") { guardian.trust(alert) }
        case .process:
            if alert.pid != nil { Button("结束进程") { guardian.kill(alert) } }
            if let exe = alert.executable { Button("显示") { guardian.reveal(exe) } }
            if alert.event { Button("知道了") { guardian.dismiss(alert) } } else { Button("信任") { guardian.trust(alert) } }
        case .config:
            if let path = alert.path { Button("显示") { guardian.reveal(path) } }
            Button("信任") { guardian.trust(alert) }
        case .command:
            Button("知道了") { guardian.dismiss(alert) }
        case .system:
            EmptyView()
        }
    }
}

private struct LaunchItemRow: View {
    @EnvironmentObject private var guardian: SecurityGuard
    let item: LaunchItemInfo

    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 4) {
                    Text(item.label).font(.caption).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 2)
                    Text(item.scope).font(.caption2).foregroundStyle(.tertiary)
                }
                Text("\(item.signer.text) · \(item.target ?? "—")")
                    .font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
        .contentShape(Rectangle())
        .help(item.plist)
        .onTapGesture(count: 2) { guardian.reveal(item.plist) }
        .contextMenu {
            Button("显示启动项文件") { guardian.reveal(item.plist) }
            if let target = item.target, target.hasPrefix("/") { Button("显示程序") { guardian.reveal(target) } }
        }
    }

    private var icon: String {
        if let s = item.severity, s >= .warning { return "exclamationmark.triangle.fill" }
        return item.signer.trusted ? "checkmark.seal.fill" : "seal"
    }

    private var color: Color {
        switch item.severity {
        case .critical?: return .red
        case .warning?: return .orange
        default: return item.signer.trusted ? .green : .secondary
        }
    }
}

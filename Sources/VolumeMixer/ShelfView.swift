import SwiftUI
import QuickLookThumbnailing
import UniformTypeIdentifiers

/// 素材 page: the old 素材夹 popover, sized for 一览's 320pt popover.
struct ShelfView: View {
    @EnvironmentObject private var shelf: Shelf
    @State private var dropTargeted = false

    private let columns = Array(repeating: GridItem(.fixed(ShelfView.tile), spacing: 8), count: 3)
    static let tile: CGFloat = 90

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header

            Group {
                if shelf.items.isEmpty {
                    emptyState
                } else {
                    ScrollView {
                        LazyVGrid(columns: columns, spacing: 8) {
                            ForEach(shelf.items) { item in
                                TileView(item: item)
                            }
                        }
                        .padding(2)
                    }
                    .frame(maxHeight: 340)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            .overlay {
                if dropTargeted {
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6]))
                }
            }

            footer
        }
        .onDrop(of: [.fileURL, .image], isTargeted: $dropTargeted) { providers in
            load(providers)
            return true
        }
        .background {
            // ⌘V while the shelf is open.
            Button("") { shelf.pasteFromClipboard() }
                .keyboardShortcut("v")
                .hidden()
        }
    }

    private var header: some View {
        HStack {
            Text("素材").font(.headline)
            Text("\(shelf.items.count)")
                .font(.caption).monospacedDigit()
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                shelf.pasteFromClipboard()
            } label: {
                Image(systemName: "doc.on.clipboard")
            }
            .buttonStyle(.borderless)
            .help("从剪贴板添加（⌘V）")
            Button {
                NSWorkspace.shared.open(shelf.directory)
            } label: {
                Image(systemName: "folder")
            }
            .buttonStyle(.borderless)
            .help("在访达中打开")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: 30))
                .foregroundStyle(.secondary)
            Text("把截图或文件拖到这里，或拖到菜单栏图标上")
                .foregroundStyle(.secondary)
            Text("也可以 ⌘V 粘贴剪贴板里的图片")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 28)
    }

    private var footer: some View {
        HStack {
            Toggle("自动收集新截图", isOn: $shelf.collectScreenshots)
                .toggleStyle(.checkbox)
            Spacer()
            Button("清空") { shelf.clear() }
                .disabled(shelf.items.isEmpty)
        }
        .controlSize(.small)
    }

    private func load(_ providers: [NSItemProvider]) {
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    guard let url else { return }
                    Task { @MainActor in shelf.add(fileURLs: [url]) }
                }
            } else if provider.hasItemConformingToTypeIdentifier(UTType.image.identifier) {
                provider.loadDataRepresentation(forTypeIdentifier: UTType.image.identifier) { data, _ in
                    guard let data, let png = NSImage(data: data)?.pngData else { return }
                    Task { @MainActor in shelf.add(imageData: png, ext: "png") }
                }
            }
        }
    }
}

struct TileView: View {
    @EnvironmentObject private var shelf: Shelf
    let item: ShelfItem
    @State private var thumbnail: NSImage?
    @State private var hovering = false

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            Group {
                if let thumbnail {
                    Image(nsImage: thumbnail)
                        .resizable()
                        .scaledToFit()
                } else {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: item.url.path))
                        .resizable()
                        .scaledToFit()
                        .padding(14)
                }
            }
            .frame(width: ShelfView.tile, height: ShelfView.tile)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            Text(item.format)
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(badgeColor, in: RoundedRectangle(cornerRadius: 4))
                .padding(5)
        }
        .overlay(alignment: .topTrailing) {
            if hovering {
                Button {
                    shelf.remove(item)
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, .black.opacity(0.6))
                        .font(.system(size: 16))
                }
                .buttonStyle(.plain)
                .padding(4)
                .help("移出")
            }
        }
        .onHover { hovering = $0 }
        .help(item.name)
        .onTapGesture(count: 2) { NSWorkspace.shared.open(item.url) }
        .onDrag { NSItemProvider(contentsOf: item.url) ?? NSItemProvider() }
        .contextMenu {
            Button("打开") { NSWorkspace.shared.open(item.url) }
            Button("拷贝") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.writeObjects([item.url as NSURL])
            }
            Button("在访达中显示") { NSWorkspace.shared.activateFileViewerSelecting([item.url]) }
            Divider()
            Button("移出") { shelf.remove(item) }
        }
        .task(id: item.url) { thumbnail = await Self.thumbnail(for: item.url) }
    }

    /// Images, video, PDF and documents each get their own badge tint.
    private var badgeColor: Color {
        guard let type = UTType(filenameExtension: item.url.pathExtension) else { return .gray }
        if type.conforms(to: .image) { return .blue }
        if type.conforms(to: .movie) || type.conforms(to: .video) { return .purple }
        if type.conforms(to: .pdf) { return .red }
        if type.conforms(to: .audio) { return .orange }
        return .gray
    }

    private static func thumbnail(for url: URL) async -> NSImage? {
        let scale = NSScreen.main?.backingScaleFactor ?? 2
        let request = QLThumbnailGenerator.Request(fileAt: url, size: CGSize(width: 108, height: 108),
                                                   scale: scale, representationTypes: .thumbnail)
        return try? await QLThumbnailGenerator.shared.generateBestRepresentation(for: request).nsImage
    }
}

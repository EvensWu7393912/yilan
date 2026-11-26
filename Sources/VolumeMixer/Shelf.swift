import AppKit
import Combine
import UniformTypeIdentifiers

struct ShelfItem: Identifiable, Hashable {
    let url: URL
    let added: Date
    var id: URL { url }
    var name: String { url.lastPathComponent }
    /// Shown in the thumbnail's bottom-right badge.
    var format: String {
        let ext = url.pathExtension.uppercased()
        return ext.isEmpty ? "FILE" : (ext == "JPEG" ? "JPG" : ext)
    }
}

/// The 素材 page (formerly the standalone 素材夹 app). The shelf is a plain folder: every item is
/// a copy kept there, so originals can be moved or deleted freely and the shelf survives restarts
/// without any extra index. It keeps 素材夹's folder, so existing items carry over.
@MainActor
final class Shelf: ObservableObject {
    @Published private(set) var items: [ShelfItem] = []
    @Published var collectScreenshots: Bool {
        didSet {
            UserDefaults.standard.set(collectScreenshots, forKey: "shelfCollectScreenshots")
            updateWatcher()
        }
    }

    /// Copies and clipboard screenshots (⌃⇧⌘4, or screenshots set to go to the clipboard) never
    /// touch the screenshot folder, so the clipboard is watched separately.
    @Published var collectClipboard: Bool {
        didSet {
            UserDefaults.standard.set(collectClipboard, forKey: "shelfCollectClipboard")
            updateClipboardWatcher()
        }
    }

    /// Items older than this many days go to the Trash; 0 keeps everything.
    @Published var retentionDays: Int {
        didSet {
            UserDefaults.standard.set(retentionDays, forKey: "shelfRetentionDays")
            pruneExpired()
        }
    }
    static let retentionPresets = [1, 3, 7, 30]

    let directory: URL
    private var pruneTimer: Timer?
    private var clipboardTimer: Timer?
    private var lastChangeCount = NSPasteboard.general.changeCount
    /// The clipboard state already on the shelf, so a later ⌘V doesn't add it twice.
    private var collectedChangeCount = -1
    private let fm = FileManager.default
    private var watcher: DirectoryWatcher?
    private var shelfWatcher: DirectoryWatcher?
    /// Copies run here one at a time, so a large file never freezes the menu bar and names stay unique.
    private let copyQueue = DispatchQueue(label: "VolumeMixer.shelf", qos: .userInitiated)

    init() {
        directory = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("素材夹", isDirectory: true)
        try? fm.createDirectory(at: directory, withIntermediateDirectories: true)
        collectScreenshots = UserDefaults.standard.object(forKey: "shelfCollectScreenshots") as? Bool ?? true
        collectClipboard = UserDefaults.standard.object(forKey: "shelfCollectClipboard") as? Bool ?? true
        retentionDays = UserDefaults.standard.object(forKey: "shelfRetentionDays") as? Int ?? 1
        reload()
        pruneExpired()
        updateWatcher()
        updateClipboardWatcher()
        let timer = Timer(timeInterval: 600, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.pruneExpired() }
        }
        timer.tolerance = 60
        RunLoop.main.add(timer, forMode: .common)
        pruneTimer = timer
        // Files added or removed in Finder show up here too, so the shelf never shows stale items.
        shelfWatcher = DirectoryWatcher(url: directory, onChange: { [weak self] _ in
            Task { @MainActor in self?.reload() }
        })
    }

    func reload() {
        let keys: [URLResourceKey] = [.creationDateKey]
        let urls = (try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: keys,
                                                options: [.skipsHiddenFiles])) ?? []
        items = urls.map { url in
            ShelfItem(url: url, added: (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast)
        }
        .sorted { $0.added > $1.added }
    }

    // MARK: Adding

    func add(fileURLs: [URL]) {
        let directory = directory
        let inside = directory.standardizedFileURL.path + "/"
        let sources = fileURLs.filter { !$0.standardizedFileURL.path.hasPrefix(inside) }
        guard !sources.isEmpty else { return }
        copyQueue.async { [weak self] in
            let fm = FileManager.default
            for url in sources {
                let target = Self.uniqueURL(for: url.lastPathComponent, in: directory)
                guard (try? fm.copyItem(at: url, to: target)) != nil else { continue }
                // Copies keep the original creation date; reset it so the newest addition sorts first.
                try? fm.setAttributes([.creationDate: Date(), .modificationDate: Date()], ofItemAtPath: target.path)
            }
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.reload() } }
        }
    }

    func add(imageData: Data, ext: String) {
        let stamp = Self.stampFormatter.string(from: Date())
        let directory = directory
        copyQueue.async { [weak self] in
            try? imageData.write(to: Self.uniqueURL(for: "粘贴 \(stamp).\(ext)", in: directory))
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.reload() } }
        }
    }

    /// Reads whatever is on the clipboard: copied files first, then raw image data
    /// (⌃⇧⌘4 screenshots land here as image data, not files).
    @discardableResult
    func pasteFromClipboard() -> Bool {
        let pb = NSPasteboard.general
        if pb.changeCount == collectedChangeCount { return true }
        if let urls = pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
           !urls.isEmpty {
            add(fileURLs: urls)
            return true
        }
        if let data = pb.data(forType: .png) {
            add(imageData: data, ext: "png")
            return true
        }
        if let image = NSImage(pasteboard: pb), let data = image.pngData {
            add(imageData: data, ext: "png")
            return true
        }
        return false
    }

    /// Shared by the menu bar icon and the popover: files win, otherwise any image.
    func accept(pasteboard pb: NSPasteboard) -> Bool {
        if let urls = pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
           !urls.isEmpty {
            add(fileURLs: urls)
            return true
        }
        if let image = NSImage(pasteboard: pb), let data = image.pngData {
            add(imageData: data, ext: "png")
            return true
        }
        return false
    }

    // MARK: Removing

    func remove(_ item: ShelfItem) {
        try? fm.trashItem(at: item.url, resultingItemURL: nil)
        reload()
    }

    func clear() {
        for item in items { try? fm.trashItem(at: item.url, resultingItemURL: nil) }
        reload()
    }

    // MARK: Expiry

    static func retentionTitle(_ days: Int) -> String {
        days == 0 ? "不自动清理" : "保留 \(days) 天"
    }

    /// Moves items added more than `retentionDays` days ago to the Trash.
    func pruneExpired() {
        guard retentionDays > 0 else { return }
        let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86_400)
        let expired = items.filter { $0.added < cutoff }
        guard !expired.isEmpty else { return }
        for item in expired { try? fm.trashItem(at: item.url, resultingItemURL: nil) }
        reload()
    }

    /// Asks for a custom number of days; 0 turns cleanup off.
    func promptCustomRetention() {
        let alert = NSAlert()
        alert.messageText = "素材保留几天？"
        alert.informativeText = "超过这个天数的素材会移到废纸篓。填 0 表示不自动清理。"
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 120, height: 24))
        field.stringValue = String(retentionDays)
        field.placeholderString = "天数"
        alert.accessoryView = field
        alert.addButton(withTitle: "好")
        alert.addButton(withTitle: "取消")
        alert.window.initialFirstResponder = field
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let text = field.stringValue.trimmingCharacters(in: .whitespaces)
        if let days = Int(text), days >= 0, days <= 3650 { retentionDays = days }
    }

    // MARK: Helpers

    nonisolated private static func uniqueURL(for name: String, in directory: URL) -> URL {
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        var candidate = directory.appendingPathComponent(name)
        var n = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = directory.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
            n += 1
        }
        return candidate
    }

    private static let stampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return f
    }()

    // MARK: Clipboard collection

    private func updateClipboardWatcher() {
        clipboardTimer?.invalidate()
        clipboardTimer = nil
        guard collectClipboard else { return }
        lastChangeCount = NSPasteboard.general.changeCount
        // NSPasteboard has no change notification; polling changeCount is cheap.
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkClipboard() }
        }
        timer.tolerance = 0.2
        RunLoop.main.add(timer, forMode: .common)
        clipboardTimer = timer
    }

    private static let skippedTypes: Set<String> = [
        "org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType", "org.nspasteboard.AutoGeneratedType",
        "com.agilebits.onepassword", "de.petermaurer.TransientPasteboardType",
    ]
    /// Copying a huge file in Finder just to move it shouldn't duplicate it here.
    private static let maxAutoFileSize = 200 * 1024 * 1024

    private func checkClipboard() {
        let pb = NSPasteboard.general
        guard pb.changeCount != lastChangeCount else { return }
        lastChangeCount = pb.changeCount
        let types = Set((pb.types ?? []).map(\.rawValue))
        guard types.isDisjoint(with: Self.skippedTypes) else { return }

        if let urls = pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
           !urls.isEmpty {
            let files = urls.filter { url in
                let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                return values?.isRegularFile == true && (values?.fileSize ?? 0) <= Self.maxAutoFileSize
            }
            if !files.isEmpty {
                add(fileURLs: files)
                collectedChangeCount = pb.changeCount
            }
            return
        }
        if let data = pb.data(forType: .png) {
            add(imageData: data, ext: "png")
        } else if pb.availableType(from: [.tiff]) != nil, let image = NSImage(pasteboard: pb), let data = image.pngData {
            add(imageData: data, ext: "png")
        } else {
            return
        }
        collectedChangeCount = pb.changeCount
    }

    // MARK: Screenshot collection

    private func updateWatcher() {
        watcher = nil
        guard collectScreenshots else { return }
        let folder = Self.screenshotFolder
        watcher = DirectoryWatcher(url: folder, onChange: { [weak self] newFiles in
            Task { @MainActor in
                let shots = newFiles.filter(Self.isScreenshot)
                if !shots.isEmpty { self?.add(fileURLs: shots) }
            }
        })
    }

    static var screenshotFolder: URL {
        if let path = UserDefaults(suiteName: "com.apple.screencapture")?.string(forKey: "location") {
            let expanded = (path as NSString).expandingTildeInPath
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir), isDir.boolValue {
                return URL(fileURLWithPath: expanded, isDirectory: true)
            }
        }
        return FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask)[0]
    }

    /// screencapture tags its files with this attribute, regardless of the system language.
    nonisolated static func isScreenshot(_ url: URL) -> Bool {
        getxattr(url.path, "com.apple.metadata:kMDItemIsScreenCapture", nil, 0, 0, 0) > 0
    }
}

/// Calls back whenever a folder's (non-hidden, top-level) listing changes, passing the newly added files.
final class DirectoryWatcher {
    private let source: DispatchSourceFileSystemObject
    private var known: Set<String>
    private let url: URL

    init?(url: URL, onChange: @escaping ([URL]) -> Void) {
        let fd = open(url.path, O_EVTONLY)
        guard fd >= 0 else { return nil }
        self.url = url
        known = Self.listing(url)
        source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .write, queue: .main)
        source.setEventHandler { [weak self] in
            // screencapture writes a hidden temp file and renames it; give it a moment to settle.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                guard let self else { return }
                let now = Self.listing(self.url)
                guard now != self.known else { return }
                let added = now.subtracting(self.known)
                self.known = now
                onChange(added.map { self.url.appendingPathComponent($0) })
            }
        }
        source.setCancelHandler { close(fd) }
        source.resume()
    }

    deinit { source.cancel() }

    private static func listing(_ url: URL) -> Set<String> {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        return Set(names.filter { !$0.hasPrefix(".") })
    }
}

extension NSImage {
    var pngData: Data? {
        guard let tiff = tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) else { return nil }
        return rep.representation(using: .png, properties: [:])
    }
}

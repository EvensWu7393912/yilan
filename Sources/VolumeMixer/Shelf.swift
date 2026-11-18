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

    let directory: URL
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
        reload()
        updateWatcher()
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

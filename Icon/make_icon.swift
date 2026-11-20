// Draws 一览's app icon: a menu bar strip ("一") with a panel hanging from it, three readouts at a glance.
// Usage: swift Icon/make_icon.swift <out.png> [size]
import AppKit

let out = CommandLine.arguments[1]
let size = CGFloat(Double(CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "1024")!)
let s = size / 1024

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext
ctx.scaleBy(x: s, y: s)
// Flip so y grows downward, like a design tool.
ctx.translateBy(x: 0, y: 1024)
ctx.scaleBy(x: 1, y: -1)

func color(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat(hex >> 16 & 0xff) / 255, green: CGFloat(hex >> 8 & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: a)
}
let space = CGColorSpaceCreateDeviceRGB()

// Squircle body (macOS grid: 824 pt body on a 1024 canvas).
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let bodyPath = CGPath(roundedRect: body, cornerWidth: 186, cornerHeight: 186, transform: nil)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -14 * s), blur: 30 * s, color: color(0x000000, 0.35))
ctx.addPath(bodyPath); ctx.setFillColor(color(0x1b2140)); ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(bodyPath); ctx.clip()
let bg = CGGradient(colorsSpace: space, colors: [color(0x2b3a8f), color(0x151b3d)] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(bg, start: CGPoint(x: 512, y: 100), end: CGPoint(x: 512, y: 924), options: [])
// Soft glow under the bar.
let glow = CGGradient(colorsSpace: space, colors: [color(0x6f8cff, 0.45), color(0x6f8cff, 0)] as CFArray, locations: [0, 1])!
ctx.drawRadialGradient(glow, startCenter: CGPoint(x: 512, y: 330), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 330), endRadius: 430, options: [])

// The panel hanging from the bar.
let panel = CGRect(x: 262, y: 330, width: 500, height: 440)
let panelPath = CGPath(roundedRect: panel, cornerWidth: 64, cornerHeight: 64, transform: nil)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -18 * s), blur: 40 * s, color: color(0x05081a, 0.5))
ctx.addPath(panelPath); ctx.setFillColor(color(0xf4f6ff)); ctx.fillPath()
ctx.restoreGState()
// Little pointer joining panel and bar.
ctx.move(to: CGPoint(x: 472, y: 334)); ctx.addLine(to: CGPoint(x: 512, y: 292)); ctx.addLine(to: CGPoint(x: 552, y: 334))
ctx.closePath(); ctx.setFillColor(color(0xf4f6ff)); ctx.fillPath()

// Three readouts: rounded level bars in the app's accent colors.
let rows: [(CGFloat, UInt32)] = [(0.78, 0x4f7bff), (0.52, 0x34c38f), (0.32, 0xff9f43)]
for (i, row) in rows.enumerated() {
    let y = 400 + CGFloat(i) * 110
    let track = CGRect(x: 322, y: y, width: 380, height: 52)
    ctx.addPath(CGPath(roundedRect: track, cornerWidth: 26, cornerHeight: 26, transform: nil))
    ctx.setFillColor(color(0xdde2f5)); ctx.fillPath()
    let fill = CGRect(x: 322, y: y, width: 380 * row.0, height: 52)
    ctx.addPath(CGPath(roundedRect: fill, cornerWidth: 26, cornerHeight: 26, transform: nil))
    ctx.setFillColor(color(row.1)); ctx.fillPath()
}

// The bar itself: one bold stroke, "一".
let bar = CGRect(x: 196, y: 226, width: 632, height: 72)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -6 * s), blur: 16 * s, color: color(0x05081a, 0.45))
ctx.addPath(CGPath(roundedRect: bar, cornerWidth: 36, cornerHeight: 36, transform: nil))
ctx.setFillColor(color(0xffffff)); ctx.fillPath()
ctx.restoreGState()
// Top sheen.
let sheen = CGGradient(colorsSpace: space, colors: [color(0xffffff, 0.14), color(0xffffff, 0)] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(sheen, start: CGPoint(x: 512, y: 100), end: CGPoint(x: 512, y: 420), options: [])
ctx.restoreGState()

NSGraphicsContext.current = nil
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))

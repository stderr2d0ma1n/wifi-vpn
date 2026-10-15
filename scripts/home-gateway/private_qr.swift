// Generate a private JSON or explicit UTF-8 text QR locally; no network.
// Usage: swift -module-cache-path PRIVATE_CACHE private_qr.swift INPUT NEW_PNG [--text]
import Foundation
import CoreImage
import ImageIO
import UniformTypeIdentifiers

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}
guard CommandLine.arguments.count == 3 ||
      (CommandLine.arguments.count == 4 && CommandLine.arguments[3] == "--text")
else { fail("Expected INPUT NEW_PNG [--text]") }
let source = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL.resolvingSymlinksInPath()
let target = URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL.resolvingSymlinksInPath()
let manager = FileManager.default
guard !manager.fileExists(atPath: target.path) else { fail("Destination already exists") }
var ancestor = target.deletingLastPathComponent()
while true {
    if manager.fileExists(atPath: ancestor.appendingPathComponent(".git").path) {
        fail("Private QR must stay outside Git")
    }
    let parent = ancestor.deletingLastPathComponent()
    if parent.path == ancestor.path { break }
    ancestor = parent
}
do {
    let raw = try Data(contentsOf: source)
    let payload: Data
    if CommandLine.arguments.count == 4 {
        guard let text = String(data: raw, encoding: .utf8) else { fail("Expected UTF-8 text") }
        payload = Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
    } else {
        let object = try JSONSerialization.jsonObject(with: raw)
        payload = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
    guard !payload.isEmpty && payload.count <= 2200 else { fail("Payload size is invalid for this QR export") }
    guard let filter = CIFilter(name: "CIQRCodeGenerator") else { fail("QR generator unavailable") }
    filter.setValue(payload, forKey: "inputMessage")
    filter.setValue("M", forKey: "inputCorrectionLevel")
    guard let matrix = filter.outputImage else { fail("QR generation failed") }
    let bounds = CGRect(x: 0, y: 0, width: matrix.extent.width + 8, height: matrix.extent.height + 8)
    let background = CIImage(color: CIColor.white).cropped(to: bounds)
    let padded = matrix.transformed(by: CGAffineTransform(translationX: 4, y: 4)).composited(over: background)
    let scaled = padded.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
    guard let pixels = CIContext().createCGImage(scaled, from: scaled.extent),
          let output = CGImageDestinationCreateWithURL(target as CFURL, UTType.png.identifier as CFString, 1, nil)
    else { fail("PNG destination could not be created") }
    CGImageDestinationAddImage(output, pixels, nil)
    guard CGImageDestinationFinalize(output) else { fail("PNG write failed") }
    try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
    // Verify that the QR decodes back to the same bytes before handing it over.
    guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: CIContext(), options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]),
          let image = CIImage(contentsOf: target),
          let feature = detector.features(in: image).first as? CIQRCodeFeature,
          feature.messageString == String(data: payload, encoding: .utf8)
    else { try? manager.removeItem(at: target); fail("Local QR readback verification failed") }
    print("Private QR generated and decoded locally; credential values not printed.")
} catch {
    fail("Private QR export failed; input details suppressed")
}

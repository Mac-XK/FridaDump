import Foundation

struct AppItem: Identifiable, Hashable {
    let id: String
    let name: String
    let pid: UInt32
    var running: Bool { pid != 0 }
}

/// 接收注入脚本回传的消息，负责落盘与打包。
/// 所有方法都在自己的串行队列上执行，避免阻塞 UI。
final class DumpReceiver: @unchecked Sendable {

    private let queue = DispatchQueue(label: "frida.dump.receiver")
    private let outputDir: URL
    private let payloadDir: URL
    private(set) var appBundleName: String

    private var handle: FileHandle?
    private var currentRel: String = ""
    private var currentBytes: Int64 = 0
    private var totalBytes: Int64 = 0
    private var fileCount = 0

    var onLog: (@Sendable (String) -> Void)?
    var onProgress: (@Sendable (Int64, String) -> Void)?
    var onFinished: (@Sendable (Result<URL, Error>) -> Void)?

    init(outputDir: URL, appName: String) {
        self.outputDir = outputDir
        self.payloadDir = outputDir.appendingPathComponent("Payload", isDirectory: true)
        self.appBundleName = appName
    }

    // MARK: - 入口

    func consume(json: String, data: Data?) {
        queue.async { self.handle(json: json, data: data) }
    }

    // MARK: - 解析

    private func handle(json: String, data: Data?) {
        guard
            let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
            let type = obj["type"] as? String
        else { return }

        switch type {
        case "error":
            let desc = obj["description"] as? String ?? "unknown"
            onLog?("JS 错误: \(desc)")
            finishWithError(desc)
        case "log":
            if let msg = obj["payload"] as? String { onLog?(msg) }
        case "send":
            guard let payload = obj["payload"] as? [String: Any] else { return }
            handlePayload(payload, data: data)
        default:
            break
        }
    }

    private func handlePayload(_ p: [String: Any], data: Data?) {
        guard let kind = p["t"] as? String else { return }

        switch kind {
        case "log":
            onLog?(p["m"] as? String ?? "")

        case "app":
            if let name = p["name"] as? String { appBundleName = name }
            onLog?("目标: \(appBundleName)")

        case "module":
            onLog?("解密 \(p["p"] as? String ?? "")")

        case "begin":
            beginFile(rel: p["p"] as? String ?? "", size: Int64(p["s"] as? Int ?? 0))

        case "chunk":
            if let d = data { writeChunk(d) }

        case "end":
            closeFile()
            fileCount += 1

        case "skip":
            break   // SC_Info 等受保护文件打不开属正常，不刷屏

        case "done":
            finish()

        case "error":
            finishWithError(p["m"] as? String ?? "脚本异常")

        default:
            break
        }
    }

    // MARK: - 落盘

    private func beginFile(rel: String, size: Int64) {
        closeFile()

        guard !rel.contains("..") else {
            onLog?("非法路径已忽略: \(rel)")
            return
        }

        let target = payloadDir.appendingPathComponent(rel)
        let dir = target.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        FileManager.default.createFile(atPath: target.path, contents: nil)
        handle = try? FileHandle(forWritingTo: target)
        currentRel = rel
        currentBytes = 0
    }

    private func writeChunk(_ d: Data) {
        guard let h = handle else { return }
        try? h.write(contentsOf: d)
        currentBytes += Int64(d.count)
        totalBytes += Int64(d.count)
        onProgress?(totalBytes, currentRel)
    }

    private func closeFile() {
        try? handle?.close()
        handle = nil
    }

    // MARK: - 收尾

    private func finish() {
        closeFile()
        onLog?("接收完成：\(fileCount) 个文件，\(ByteCountFormatter.string(fromByteCount: totalBytes, countStyle: .file))")

        do {
            let ipa = try makeIPA()
            try? FileManager.default.removeItem(at: payloadDir)   // 中间产物，打包后清掉
            onLog?("已生成 \(ipa.lastPathComponent)")
            onFinished?(.success(ipa))
        } catch {
            onFinished?(.failure(error))
        }
    }

    private func finishWithError(_ msg: String) {
        closeFile()
        onFinished?(.failure(NSError(domain: "FridaDump", code: -1,
                                     userInfo: [NSLocalizedDescriptionKey: msg])))
    }

    private func makeIPA() throws -> URL {
        guard FileManager.default.fileExists(atPath: payloadDir.path) else {
            throw NSError(domain: "FridaDump", code: -2,
                          userInfo: [NSLocalizedDescriptionKey: "Payload 不存在"])
        }

        let ipaName = (appBundleName as NSString).deletingPathExtension + ".ipa"
        let ipaURL = outputDir.appendingPathComponent(ipaName)
        try? FileManager.default.removeItem(at: ipaURL)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        proc.arguments = ["-qry", ipaURL.path, "Payload", "-x", "*.fid", "-x", "*.DS_Store"]
        proc.currentDirectoryURL = outputDir
        try proc.run()
        proc.waitUntilExit()

        guard proc.terminationStatus == 0, FileManager.default.fileExists(atPath: ipaURL.path) else {
            throw NSError(domain: "FridaDump", code: -3,
                          userInfo: [NSLocalizedDescriptionKey: "zip 打包失败"])
        }
        return ipaURL
    }
}

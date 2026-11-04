import Foundation

/// 命令行入口：FridaDump --dump <bundleID> --out <目录>
/// 复用与 GUI 完全相同的 C 桥接 / 注入脚本 / 落盘逻辑，便于自动化验证。
enum HeadlessRunner {

    static func runIfRequested() {
        let args = CommandLine.arguments
        guard let idx = args.firstIndex(of: "--dump"), idx + 1 < args.count else { return }

        let bundleID = args[idx + 1]
        var outputPath = FileManager.default.currentDirectoryPath
        if let oidx = args.firstIndex(of: "--out"), oidx + 1 < args.count {
            outputPath = args[oidx + 1]
        }

        let outURL = URL(fileURLWithPath: outputPath, isDirectory: true)
        try? FileManager.default.createDirectory(at: outURL, withIntermediateDirectories: true)

        setvbuf(stdout, nil, _IONBF, 0)
        print("== FridaDump headless: \(bundleID) -> \(outURL.path)")

        fdb_init()

        let receiver = DumpReceiver(outputDir: outURL, appName: bundleID)
        let done = DispatchSemaphore(value: 0)
        var exitCode: Int32 = 0

        receiver.onLog = { print($0) }
        receiver.onProgress = { bytes, file in
            print("  \(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file))  \(file)")
        }
        receiver.onFinished = { result in
            switch result {
            case .success(let url):
                print("== OK \(url.path)")
            case .failure(let error):
                print("== FAIL \(error.localizedDescription)")
                exitCode = 1
            }
            done.signal()
        }

        var errPtr: UnsafeMutablePointer<CChar>?
        let ctx = Unmanaged.passUnretained(receiver).toOpaque()
        let rc = DumpScript.source.withCString { src in
            fdb_start_dump(bundleID, src, fridaMessageCallbackGlobal, ctx, &errPtr)
        }

        if rc != 0 {
            var msg = "start_dump failed (\(rc))"
            if let errPtr = errPtr {
                msg = String(cString: errPtr)
                free(errPtr)
            }
            print("== FAIL \(msg)")
            exit(1)
        }

        fdb_post("{\"cmd\":\"dump\"}")

        if done.wait(timeout: .now() + 600) == .timedOut {
            print("== FAIL timeout")
            exit(2)
        }
        exit(exitCode)
    }
}

/// 与 FridaService 共用的 C 回调（供无头模式使用）
let fridaMessageCallbackGlobal: FDBMessageCallback = { jsonPtr, dataPtr, length, ctx in
    guard let ctx = ctx else { return }
    let receiver = Unmanaged<DumpReceiver>.fromOpaque(ctx).takeUnretainedValue()
    let json = jsonPtr.map { String(cString: $0) } ?? "{}"
    var data: Data?
    if let dataPtr = dataPtr, length > 0 {
        data = Data(bytes: dataPtr, count: length)
    }
    receiver.consume(json: json, data: data)
}

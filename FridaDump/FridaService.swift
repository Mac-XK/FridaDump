import Foundation
import Combine

@MainActor
final class FridaService: ObservableObject {

    @Published var apps: [AppItem] = []
    @Published var deviceName: String = ""
    @Published var logs: [String] = []
    @Published var isBusy = false
    @Published var status: String = "准备中…"
    @Published var progressBytes: Int64 = 0
    @Published var currentFile: String = ""
    @Published var lastIPA: URL?

    private let work = DispatchQueue(label: "frida.work")
    private var receiver: DumpReceiver?
    private var started = false

    // MARK: - 生命周期

    func bootstrap() {
        guard !started else { return }
        started = true
        work.async {
            fdb_init()
            DispatchQueue.main.async { self.status = "已就绪" }
        }
    }

    // MARK: - 设备 / 应用列表

    func refreshApps() {
        isBusy = true
        status = "正在读取设备…"

        work.async {
            let namePtr = fdb_device_name()
            let name = namePtr.map { String(cString: $0) } ?? ""
            if let p = namePtr { free(p) }

            var errPtr: UnsafeMutablePointer<CChar>?
            let jsonPtr = fdb_enumerate_apps(&errPtr)
            var apps: [AppItem] = []
            var errorText: String?

            if let jsonPtr = jsonPtr {
                let json = String(cString: jsonPtr)
                free(jsonPtr)
                apps = Self.decodeApps(json)
            } else if let errPtr = errPtr {
                errorText = String(cString: errPtr)
                free(errPtr)
            }

            DispatchQueue.main.async {
                self.isBusy = false
                self.deviceName = name
                self.apps = apps.sorted { a, b in
                    if a.running != b.running { return a.running }
                    return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
                }
                if let e = errorText {
                    self.status = "设备错误"
                    self.append("❌ \(e)")
                } else {
                    self.status = "\(apps.count) 个 App · \(name)"
                    self.append("已连接 \(name)，共 \(apps.count) 个 App")
                }
            }
        }
    }

    private static func decodeApps(_ json: String) -> [AppItem] {
        guard let data = json.data(using: .utf8),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }

        return raw.compactMap { item in
            guard let id = item["identifier"] as? String else { return nil }
            let name = item["name"] as? String ?? id
            let pid = UInt32(item["pid"] as? Int ?? 0)
            return AppItem(id: id, name: name, pid: pid)
        }
    }

    // MARK: - 环境自检

    func diagnose(completion: @escaping ([DiagnoseItem]) -> Void) {
        work.async {
            fdb_init()
            var items: [DiagnoseItem] = []

            let namePtr = fdb_device_name()
            let name = namePtr.map { String(cString: $0) } ?? ""
            if let p = namePtr { free(p) }
            items.append(DiagnoseItem(
                title: "USB 设备连接",
                ok: !name.isEmpty,
                detail: name.isEmpty ? "未发现 USB 设备" : "已识别：\(name)",
                fix: "用数据线连接 iPhone，并在手机上点「信任此电脑」"))

            var errPtr: UnsafeMutablePointer<CChar>?
            let jsonPtr = fdb_enumerate_apps(&errPtr)
            var count = 0
            var errText: String?
            if let jsonPtr = jsonPtr {
                let json = String(cString: jsonPtr)
                free(jsonPtr)
                count = Self.decodeApps(json).count
            } else if let errPtr = errPtr {
                errText = String(cString: errPtr)
                free(errPtr)
            }
            items.append(DiagnoseItem(
                title: "frida-server 响应",
                ok: jsonPtr != nil,
                detail: jsonPtr != nil ? "通信正常（frida-core 17.25.2）" : (errText ?? "无响应"),
                fix: "设备端执行 killall frida-server（launchd 会自动拉起），并确认版本为 17.25.2"))

            items.append(DiagnoseItem(
                title: "App 列表",
                ok: count > 0,
                detail: count > 0 ? "已读到 \(count) 个 App" : "读到 0 个 App",
                fix: "确认设备已越狱且 Sileo 里装了 re.frida.server"))

            DispatchQueue.main.async { completion(items) }
        }
    }

    // MARK: - 砸壳

    func startDump(app: AppItem, outputDir: URL) {
        guard !isBusy else { return }
        isBusy = true
        progressBytes = 0
        currentFile = ""
        lastIPA = nil

        let rec = DumpReceiver(outputDir: outputDir, appName: app.name)
        receiver = rec

        rec.onLog = { msg in
            DispatchQueue.main.async { self.append(msg) }
        }
        rec.onProgress = { bytes, file in
            DispatchQueue.main.async {
                self.progressBytes = bytes
                self.currentFile = file
            }
        }
        rec.onFinished = { result in
            DispatchQueue.main.async {
                self.isBusy = false
                switch result {
                case .success(let url):
                    self.lastIPA = url
                    self.status = "完成：\(url.lastPathComponent)"
                case .failure(let error):
                    self.status = "失败：\(error.localizedDescription)"
                    self.append("❌ \(error.localizedDescription)")
                }
            }
        }

        status = "正在启动 \(app.name)…"
        append("开始砸壳 \(app.name) [\(app.id)]")

        let ctx = Unmanaged.passUnretained(rec).toOpaque()
        let script = DumpScript.source

        work.async {
            var errPtr: UnsafeMutablePointer<CChar>?
            let rc = script.withCString { src in
                fdb_start_dump(app.id, src, fridaMessageCallbackGlobal, ctx, &errPtr)
            }

            if rc != 0 {
                var msg = "启动失败 (code \(rc))"
                if let errPtr = errPtr {
                    msg = String(cString: errPtr)
                    free(errPtr)
                }
                DispatchQueue.main.async {
                    self.isBusy = false
                    self.status = "失败"
                    self.append("❌ \(msg)")
                }
                return
            }

            fdb_post("{\"cmd\":\"dump\"}")
        }
    }

    // MARK: - 日志

    func append(_ line: String) {
        let stamp = Self.formatter.string(from: Date())
        logs.append("[\(stamp)] \(line)")
        if logs.count > 600 { logs.removeFirst(logs.count - 600) }
    }

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    func clearLogs() { logs.removeAll() }
}

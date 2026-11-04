import Foundation

struct RemoteItem: Identifiable, Hashable {
    let path: String
    let name: String
    let isDir: Bool
    let size: Int64
    let modified: String
    let permissions: String

    var id: String { path }
}

enum SSHError: LocalizedError {
    case proxyFailed(String)
    case authFailed(String)
    case commandFailed(String)

    var errorDescription: String? {
        switch self {
        case .proxyFailed(let m): return "端口转发失败：\(m)"
        case .authFailed(let m): return "SSH 认证失败：\(m)"
        case .commandFailed(let m): return m
        }
    }
}

/// 通过设备自带 SSH（iproxy 2222 -> 22）做文件浏览与传输。
/// 首次会自动把本机公钥推到设备，之后全部免密。
final class SSHService: @unchecked Sendable {

    static let shared = SSHService()

    private let defaults = UserDefaults.standard

    var host: String {
        get { defaults.string(forKey: "sshHost") ?? "127.0.0.1" }
        set { defaults.set(newValue, forKey: "sshHost") }
    }
    var port: Int {
        get { defaults.object(forKey: "sshPort") as? Int ?? 2222 }
        set { defaults.set(newValue, forKey: "sshPort") }
    }
    var user: String {
        get { defaults.string(forKey: "sshUser") ?? "root" }
        set { defaults.set(newValue, forKey: "sshUser") }
    }
    var password: String {
        get { defaults.string(forKey: "sshPassword") ?? "alpine" }
        set { defaults.set(newValue, forKey: "sshPassword") }
    }

    private let queue = DispatchQueue(label: "frida.ssh")
    private var proxyProcess: Process?
    private var ready = false

    var keyPath: String {
        let dir = ("~/.ssh" as NSString).expandingTildeInPath
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir + "/fridadump_ed25519"
    }

    // MARK: - 准备

    func ensureReady() throws {
        if ready { return }
        try ensureProxy()
        try ensureKey()
        ready = true
    }

    /// 显式连接：起 iproxy -> 推公钥 -> 验证免密
    func connect() throws {
        ready = false
        try ensureProxy()
        try ensureKeyAuth()
        ready = true
    }

    /// 生成密钥（如无）
    private func ensureKey() throws {
        guard !FileManager.default.fileExists(atPath: keyPath) else { return }
        _ = try? run("/usr/bin/ssh-keygen",
                     ["-t", "ed25519", "-N", "", "-f", keyPath, "-C", "fridadump"])
    }

    /// 端口没通就起 iproxy
    private func ensureProxy() throws {
        if portOpen() { return }

        let candidates = ["/opt/homebrew/bin/iproxy", "/usr/local/bin/iproxy", "/usr/bin/iproxy"]
        guard let bin = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw SSHError.proxyFailed("找不到 iproxy，请先安装 libimobiledevice（brew install libimobiledevice）")
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["\(port)", "22"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        proxyProcess = p

        for _ in 0..<20 {
            if portOpen() { return }
            Thread.sleep(forTimeInterval: 0.25)
        }
        throw SSHError.proxyFailed("iproxy 未能监听 \(port)，检查 USB 连接")
    }

    private func portOpen() -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nc")
        p.arguments = ["-z", host, "\(port)"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    /// 免密登录，失败就用密码推一次公钥
    private func ensureKeyAuth() throws {
        if (try? runSSH(["echo", "ok"])) != nil { return }
        try pushPublicKey()
        guard (try? runSSH(["echo", "ok"])) != nil else {
            throw SSHError.authFailed("免密配置失败，请确认设备已装 openssh 且 root 密码为 alpine")
        }
    }

    private func pushPublicKey() throws {
        guard let pubKey = try? String(contentsOfFile: keyPath + ".pub", encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw SSHError.authFailed("公钥不存在")
        }

        let remote = "mkdir -p /var/jb/var/root/.ssh /var/root/.ssh 2>/dev/null; "
            + "echo '\(pubKey)' >> /var/jb/var/root/.ssh/authorized_keys 2>/dev/null; "
            + "echo '\(pubKey)' >> /var/root/.ssh/authorized_keys 2>/dev/null; "
            + "chmod 600 /var/jb/var/root/.ssh/authorized_keys /var/root/.ssh/authorized_keys 2>/dev/null; echo DONE"

        // expect -c 里的 -re 不可靠，写脚本文件 + glob 匹配才稳定
        let script = """
        set timeout 25
        spawn /usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p \(port) \(user)@\(host) "\(remote)"
        expect {
            "*assword*" { send "\(password)\r" }
            timeout { puts "TIMEOUT"; exit 1 }
        }
        expect eof
        """

        let tmp = NSTemporaryDirectory() + "fridadump_push.exp"
        try script.write(toFile: tmp, atomically: true, encoding: .utf8)
        let out = try run("/usr/bin/expect", ["-f", tmp])
        try? FileManager.default.removeItem(atPath: tmp)

        guard out.contains("DONE") else {
            throw SSHError.authFailed("推送公钥失败")
        }
    }

    // MARK: - 命令执行

    @discardableResult
    private func run(_ bin: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func runSSH(_ command: [String]) throws -> String {
        var args = [
            "-i", keyPath,
            "-p", "\(port)",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=8",
            "\(user)@\(host)",
        ]
        args.append(contentsOf: command)
        let out = try run("/usr/bin/ssh", args)
        if out.contains("Permission denied") || out.contains("Host key verification failed") {
            throw SSHError.authFailed(out)
        }
        return out
    }

    private func escape(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: - 文件操作

    func list(_ path: String) throws -> [RemoteItem] {
        try ensureReady()
        try ensureKeyAuth()

        let cmd = "find -H \(escape(path)) -maxdepth 1 -mindepth 1 "
            + "-exec stat -c '%n|%s|%F|%y|%A' {} \\; 2>/dev/null"
        let out = try runSSH([cmd])

        var items: [RemoteItem] = []
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: "|", maxSplits: 4, omittingEmptySubsequences: false)
            guard parts.count >= 5 else { continue }
            let full = String(parts[0])
            let size = Int64(parts[1]) ?? 0
            let type = String(parts[2])
            let modified = String(parts[3].prefix(16))
            let perms = String(parts[4])
            let name = (full as NSString).lastPathComponent
            guard !name.isEmpty else { continue }
            items.append(RemoteItem(path: full, name: name,
                                    isDir: type.lowercased().contains("directory"),
                                    size: size, modified: modified, permissions: perms))
        }
        return items.sorted {
            if $0.isDir != $1.isDir { return $0.isDir }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    /// 读取远端文本文件（截断到 maxBytes）
    func readText(_ remote: String, maxBytes: Int = 200_000) throws -> String {
        try ensureReady()
        try ensureKeyAuth()
        return try runSSH(["head -c \(maxBytes) \(escape(remote)) 2>/dev/null"])
    }

    func download(remote: String, to localDir: URL) throws -> URL {
        try ensureReady()
        try ensureKeyAuth()

        let dest = localDir.appendingPathComponent((remote as NSString).lastPathComponent)
        try? FileManager.default.removeItem(at: dest)

        let out = try run("/usr/bin/scp", [
            "-r",
            "-i", keyPath,
            "-P", "\(port)",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            "\(user)@\(host):\(remote)",
            dest.path,
        ])
        guard FileManager.default.fileExists(atPath: dest.path) else {
            throw SSHError.commandFailed(out.isEmpty ? "下载失败" : out)
        }
        return dest
    }

    func upload(local: URL, to remoteDir: String) throws {
        try ensureReady()
        try ensureKeyAuth()

        let out = try run("/usr/bin/scp", [
            "-r",
            "-i", keyPath,
            "-P", "\(port)",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            local.path,
            "\(user)@\(host):\(remoteDir)/",
        ])
        if out.contains("No such file") || out.contains("Permission denied") {
            throw SSHError.commandFailed(out)
        }
    }

    /// 清空目录内容（通配符不能进引号，否则不展开）
    func deleteContents(of dir: String) throws {
        try ensureReady()
        try ensureKeyAuth()
        _ = try runSSH(["find \(escape(dir)) -mindepth 1 -maxdepth 1 -exec rm -rf {} \\; 2>/dev/null; ls \(escape(dir)) | wc -l"])
    }

    func delete(remote: String) throws {
        try ensureReady()
        try ensureKeyAuth()
        _ = try runSSH(["rm -rf \(escape(remote))"])
    }
}

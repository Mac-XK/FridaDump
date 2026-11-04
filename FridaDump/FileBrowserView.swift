import SwiftUI
import Combine
import AppKit

@MainActor
final class FileBrowserModel: ObservableObject {
    @Published var path: String = "/var"
    @Published var items: [RemoteItem] = []
    @Published var isLoading = false
    @Published var status: String = "未连接"
    @Published var errorText: String?
    @Published var selection: RemoteItem?
    @Published var connected = false
    @Published var connecting = false

    private var loaded = false

    func bootstrap() {
        guard !loaded else { return }
        loaded = true
        if !connected { connect() } else { load(path) }
    }

    func connect() {
        guard !connecting else { return }
        connecting = true
        errorText = nil
        status = "连接中…"

        Task.detached(priority: .userInitiated) {
            do {
                try SSHService.shared.connect()
                await MainActor.run {
                    self.connecting = false
                    self.connected = true
                    self.status = "SSH 已连接"
                    self.load(self.path)
                }
            } catch {
                await MainActor.run {
                    self.connecting = false
                    self.connected = false
                    self.errorText = error.localizedDescription
                    self.status = "连接失败"
                }
            }
        }
    }

    func disconnect() {
        connected = false
        items = []
        status = "未连接"
    }

    func load(_ p: String) {
        isLoading = true
        errorText = nil
        status = "读取 \(p) …"

        Task.detached(priority: .userInitiated) {
            do {
                let list = try SSHService.shared.list(p)
                await MainActor.run {
                    self.path = p
                    self.items = list
                    self.isLoading = false
                    self.connected = true
                    self.status = "\(list.count) 项"
                }
            } catch {
                await MainActor.run {
                    self.isLoading = false
                    self.connected = false
                    self.errorText = error.localizedDescription
                    self.status = "读取失败"
                }
            }
        }
    }

    func enter(_ item: RemoteItem) {
        if item.isDir { load(item.path) } else { download(item) }
    }

    func up() {
        let parent = (path as NSString).deletingLastPathComponent
        if parent.isEmpty || parent == path { return }
        load(parent)
    }

    func download(_ item: RemoteItem) {
        let dir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first!
            .appendingPathComponent("FridaDump", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        status = "下载 \(item.name) …"
        Task.detached(priority: .userInitiated) {
            do {
                let url = try SSHService.shared.download(remote: item.path, to: dir)
                await MainActor.run {
                    self.status = "已保存 \(url.lastPathComponent)"
                    NSWorkspace.shared.activateFileViewerSelecting([url])
                }
            } catch {
                await MainActor.run {
                    self.errorText = error.localizedDescription
                    self.status = "下载失败"
                }
            }
        }
    }

    func upload() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.prompt = "上传到 \(path)"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        status = "上传 \(url.lastPathComponent) …"
        let target = path
        Task.detached(priority: .userInitiated) {
            do {
                try SSHService.shared.upload(local: url, to: target)
                await MainActor.run {
                    self.status = "已上传 \(url.lastPathComponent)"
                    self.load(target)
                }
            } catch {
                await MainActor.run {
                    self.errorText = error.localizedDescription
                    self.status = "上传失败"
                }
            }
        }
    }

    func delete(_ item: RemoteItem) {
        status = "删除 \(item.name) …"
        let target = path
        Task.detached(priority: .userInitiated) {
            do {
                try SSHService.shared.delete(remote: item.path)
                await MainActor.run { self.load(target) }
            } catch {
                await MainActor.run {
                    self.errorText = error.localizedDescription
                    self.status = "删除失败"
                }
            }
        }
    }
}

struct FileBrowserView: View {
    @StateObject private var model = FileBrowserModel()
    @State private var pathField = ""
    @State private var showSettings = false

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()

            if let err = model.errorText {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text(err).font(.system(size: 11)).lineLimit(3)
                    Spacer()
                    Button("配置 SSH") { showSettings = true }
                        .font(.system(size: 11))
                }
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(Color.orange.opacity(0.10))
            }

            if !model.connected && model.items.isEmpty {
                emptyState
            } else {
                List(model.items, selection: $model.selection) { item in
                    row(item)
                        .tag(item)
                        .contentShape(Rectangle())
                        .onTapGesture(count: 2) { model.enter(item) }
                        .contextMenu {
                            if item.isDir {
                                Button("打开") { model.load(item.path) }
                            } else {
                                Button("下载到 Mac") { model.download(item) }
                            }
                            Button("复制路径") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(item.path, forType: .string)
                            }
                            Divider()
                            Button("删除", role: .destructive) { model.delete(item) }
                        }
                }
                .listStyle(.inset)
            }

            Divider()
            footer
        }
        .task { model.bootstrap() }
        .onAppear { pathField = model.path }
        .onChange(of: model.path) { _, newValue in pathField = newValue }
        .sheet(isPresented: $showSettings) {
            SSHSettingsView(model: model)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "externaldrive.connected.to.line.below")
                .font(.system(size: 40)).foregroundStyle(.secondary)
            Text(model.connecting ? "正在建立 SSH 连接…" : "尚未连接设备")
                .font(.headline)
            Text("需要设备已越狱并安装 openssh（Sileo 里搜 openssh）\n默认 root / alpine，端口 2222 经 iproxy 转发")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                model.connect()
            } label: {
                Label("连接", systemImage: "bolt.horizontal.circle")
            }
            .disabled(model.connecting)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            Button { model.up() } label: { Image(systemName: "arrow.up") }
                .help("上级目录")
            Button { model.load(model.path) } label: { Image(systemName: "arrow.clockwise") }
                .help("刷新")
                .disabled(!model.connected)

            TextField("路径", text: $pathField)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 11, design: .monospaced))
                .onSubmit { model.load(pathField) }

            if model.isLoading || model.connecting {
                ProgressView().controlSize(.small)
            }

            HStack(spacing: 4) {
                Circle()
                    .fill(model.connected ? Color.green : (model.connecting ? Color.orange : Color.red))
                    .frame(width: 7, height: 7)
                Text(model.connected ? "SSH" : (model.connecting ? "连接中" : "未连接"))
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }

            Button { showSettings = true } label: { Image(systemName: "gearshape") }
                .help("SSH 配置")

            Button { model.upload() } label: {
                Label("上传", systemImage: "square.and.arrow.up")
            }
            .disabled(!model.connected)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
    }

    private func row(_ item: RemoteItem) -> some View {
        HStack(spacing: 8) {
            Image(systemName: item.isDir ? "folder.fill" : "doc.fill")
                .foregroundStyle(item.isDir ? Color.accentColor : Color.secondary)
                .frame(width: 16)

            Text(item.name)
                .font(.system(size: 12))
                .lineLimit(1)

            Spacer()

            if !item.isDir {
                Text(ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Text(item.modified)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 110, alignment: .trailing)
        }
        .padding(.vertical, 1)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Text(model.status)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Spacer()

            if let sel = model.selection {
                Button {
                    model.download(sel)
                } label: {
                    Label("下载", systemImage: "arrow.down.circle")
                }
                .disabled(sel.isDir || !model.connected)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

// MARK: - SSH 配置面板

struct SSHSettingsView: View {
    @ObservedObject var model: FileBrowserModel
    @Environment(\.dismiss) private var dismiss

    @State private var host = SSHService.shared.host
    @State private var port = "\(SSHService.shared.port)"
    @State private var user = SSHService.shared.user
    @State private var password = SSHService.shared.password

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Image(systemName: "network").foregroundStyle(.tint)
                Text("SSH 连接配置").font(.headline)
                Spacer()
                Circle()
                    .fill(model.connected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(model.connected ? "已连接" : "未连接")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                GridRow {
                    Text("主机").gridColumnAlignment(.trailing)
                    TextField("127.0.0.1", text: $host).textFieldStyle(.roundedBorder)
                }
                GridRow {
                    Text("端口")
                    TextField("2222", text: $port).textFieldStyle(.roundedBorder).frame(width: 90)
                }
                GridRow {
                    Text("用户")
                    TextField("root", text: $user).textFieldStyle(.roundedBorder)
                }
                GridRow {
                    Text("密码")
                    SecureField("alpine", text: $password).textFieldStyle(.roundedBorder)
                }
            }
            .font(.system(size: 12))

            Text("端口 2222 是 iproxy 转发出来的（设备 22 → 本机 2222）。首次连接会用上面的密码把本机公钥推到设备，之后免密。设备需已越狱并安装 openssh。")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let err = model.errorText {
                Text(err).font(.system(size: 11)).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("恢复默认") {
                    host = "127.0.0.1"; port = "2222"; user = "root"; password = "alpine"
                }
                Spacer()
                Button("取消") { dismiss() }
                Button(model.connecting ? "连接中…" : "保存并连接") {
                    SSHService.shared.host = host
                    SSHService.shared.port = Int(port) ?? 2222
                    SSHService.shared.user = user
                    SSHService.shared.password = password
                    dismiss()
                    model.connect()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(model.connecting)
            }
        }
        .padding(18)
        .frame(width: 440)
    }
}

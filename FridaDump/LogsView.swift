import SwiftUI
import Combine
import AppKit

@MainActor
final class LogsModel: ObservableObject {
    static let crashDir = "/var/mobile/Library/Logs/CrashReporter"

    @Published var items: [RemoteItem] = []
    @Published var selected: RemoteItem?
    @Published var content: String = ""
    @Published var status: String = "未加载"
    @Published var errorText: String?
    @Published var loading = false

    private var loaded = false

    func bootstrap() {
        guard !loaded else { return }
        loaded = true
        refresh()
    }

    func refresh() {
        loading = true
        errorText = nil
        status = "读取中…"

        Task.detached(priority: .userInitiated) {
            do {
                let list = try SSHService.shared.list(Self.crashDir)
                    .sorted { $0.modified > $1.modified }      // 新的在前
                await MainActor.run {
                    self.items = list
                    self.loading = false
                    self.status = "\(list.count) 个文件"
                    if let first = list.first, self.selected == nil {
                        self.open(first)
                    }
                }
            } catch {
                await MainActor.run {
                    self.loading = false
                    self.errorText = error.localizedDescription
                    self.status = "读取失败"
                }
            }
        }
    }

    func open(_ item: RemoteItem) {
        selected = item
        loading = true
        content = "读取 \(item.name) …"

        Task.detached(priority: .userInitiated) {
            do {
                let text = try SSHService.shared.readText(item.path, maxBytes: 300_000)
                await MainActor.run {
                    self.content = text.isEmpty ? "(空文件)" : text
                    self.loading = false
                }
            } catch {
                await MainActor.run {
                    self.content = "读取失败：\(error.localizedDescription)"
                    self.loading = false
                }
            }
        }
    }

    func delete(_ item: RemoteItem) {
        status = "删除 \(item.name) …"
        Task.detached(priority: .userInitiated) {
            do {
                try SSHService.shared.delete(remote: item.path)
                await MainActor.run {
                    if self.selected?.path == item.path {
                        self.selected = nil
                        self.content = ""
                    }
                    self.refresh()
                }
            } catch {
                await MainActor.run {
                    self.errorText = error.localizedDescription
                    self.status = "删除失败"
                }
            }
        }
    }

    func deleteAll() {
        status = "清空崩溃日志…"
        Task.detached(priority: .userInitiated) {
            do {
                try SSHService.shared.deleteContents(of: Self.crashDir)
                await MainActor.run {
                    self.selected = nil
                    self.content = ""
                    self.refresh()
                }
            } catch {
                await MainActor.run {
                    self.errorText = error.localizedDescription
                    self.status = "清空失败"
                }
            }
        }
    }
}

struct LogsView: View {
    @StateObject private var model = LogsModel()
    @State private var confirmClear = false

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()

            if let err = model.errorText {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text(err).font(.system(size: 11)).lineLimit(2)
                    Spacer()
                }
                .padding(.horizontal, 12).padding(.vertical, 6)
                .background(Color.orange.opacity(0.10))
            }

            HSplitView {
                list
                    .frame(minWidth: 300, idealWidth: 340)
                preview
                    .frame(minWidth: 380)
            }

            Divider()
            footer
        }
        .task { model.bootstrap() }
        .confirmationDialog("清空 CrashReporter 目录下所有日志？",
                            isPresented: $confirmClear, titleVisibility: .visible) {
            Button("全部删除", role: .destructive) { model.deleteAll() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("该操作不可撤销，设备上的崩溃与 Jetsam 记录都会被删除。")
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
                .help("刷新")

            Text(LogsModel.crashDir)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)

            if model.loading { ProgressView().controlSize(.small) }

            Spacer()

            Button {
                confirmClear = true
            } label: {
                Label("清空", systemImage: "trash")
            }
            .disabled(model.items.isEmpty)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
    }

    private var list: some View {
        List(model.items, selection: Binding(
            get: { model.selected },
            set: { if let v = $0 { model.open(v) } }
        )) { item in
            HStack(spacing: 8) {
                Image(systemName: icon(for: item.name))
                    .foregroundStyle(color(for: item.name))
                    .frame(width: 16)

                VStack(alignment: .leading, spacing: 1) {
                    Text(item.name)
                        .font(.system(size: 11.5))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(item.modified)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Text(ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 1)
            .tag(item)
            .contextMenu {
                Button("查看") { model.open(item) }
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

    private var preview: some View {
        VStack(spacing: 0) {
            HStack {
                Text(model.selected?.name ?? "未选择")
                    .font(.system(size: 11, weight: .medium))
                    .lineLimit(1).truncationMode(.middle)
                Spacer()
                if let sel = model.selected {
                    Button {
                        model.delete(sel)
                    } label: {
                        Label("删除", systemImage: "trash")
                    }
                    .buttonStyle(.link)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)

            Divider()

            ScrollView(.vertical) {
                Text(model.content)
                    .font(.system(size: 10.5, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10)
            }
        }
    }

    private var footer: some View {
        HStack {
            Text(model.status).font(.system(size: 11)).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
    }

    private func icon(for name: String) -> String {
        if name.hasPrefix("JetsamEvent") { return "memorychip" }
        if name.hasPrefix("panic") { return "exclamationmark.octagon" }
        return "doc.text"
    }

    private func color(for name: String) -> Color {
        if name.hasPrefix("JetsamEvent") { return .orange }
        if name.hasPrefix("panic") { return .red }
        return .secondary
    }
}

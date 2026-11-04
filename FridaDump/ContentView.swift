import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var service = FridaService()
    @State private var search: String = ""
    @State private var showGuide = false
    @State private var mode = 0
    @AppStorage("hasSeenGuideV2") private var hasSeenGuideV2 = false
    @State private var selection: AppItem?
    @State private var outputDir: URL = FileManager.default
        .urls(for: .downloadsDirectory, in: .userDomainMask).first
        ?? FileManager.default.homeDirectoryForCurrentUser

    private var filtered: [AppItem] {
        guard !search.isEmpty else { return service.apps }
        return service.apps.filter {
            $0.name.localizedCaseInsensitiveContains(search) ||
            $0.id.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        Group {
            if showGuide || !hasSeenGuideV2 {
                GuideView(service: service) {
                    showGuide = false
                    hasSeenGuideV2 = true
                }
            } else {
                mainView
            }
        }
    }

    private var mainView: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if mode == 0 {
                HSplitView {
                    appList
                        .frame(minWidth: 380, idealWidth: 460)
                    logPane
                        .frame(minWidth: 320)
                }
                Divider()
                footer
            } else if mode == 1 {
                FileBrowserView()
            } else {
                LogsView()
            }
        }
        .frame(minWidth: 940, minHeight: 580)
        .task {
            service.bootstrap()
            service.refreshApps()

        }

    }

    // MARK: - 顶部

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "iphone.gen3.radiowaves.left.and.right")
                .font(.title2)
                .foregroundStyle(service.apps.isEmpty ? Color.secondary : Color.accentColor)

            VStack(alignment: .leading, spacing: 2) {
                Text(service.deviceName.isEmpty ? "未连接设备" : service.deviceName)
                    .font(.headline)
                Text(service.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Picker("", selection: $mode) {
                Text("砸壳").tag(0)
                Text("文件").tag(1)
                Text("日志").tag(2)
            }
            .pickerStyle(.segmented)
            .frame(width: 190)

            if service.isBusy {
                ProgressView().controlSize(.small)
            }

            Button {
                showGuide = true
            } label: {
                Label("说明", systemImage: "questionmark.circle")
            }

            Button {
                service.refreshApps()
            } label: {
                Label("刷新", systemImage: "arrow.clockwise")
            }
            .disabled(service.isBusy)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - 应用列表

    private var appList: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("搜索 App 名称或 BundleID", text: $search)
                    .textFieldStyle(.plain)
                if !search.isEmpty {
                    Button { search = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(Color(nsColor: .textBackgroundColor))

            Divider()

            List(filtered, selection: $selection) { app in
                row(app)
                    .tag(app)
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) { startDump(app) }
            }
            .listStyle(.inset)
        }
    }

    private func row(_ app: AppItem) -> some View {
        HStack(spacing: 10) {
            Image(systemName: app.running ? "app.badge.checkmark" : "app.dashed")
                .foregroundStyle(app.running ? Color.green : Color.secondary)

            VStack(alignment: .leading, spacing: 1) {
                Text(app.name).font(.system(size: 13, weight: .medium))
                Text(app.id).font(.system(size: 11)).foregroundStyle(.secondary)
            }

            Spacer()

            if app.running {
                Text("PID \(app.pid)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    // MARK: - 日志

    private var logPane: some View {
        VStack(spacing: 0) {
            HStack {
                Text("日志").font(.system(size: 12, weight: .semibold))
                Spacer()
                Button("清空") { service.clearLogs() }
                    .buttonStyle(.link)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            Divider()

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(service.logs.enumerated()), id: \.offset) { idx, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(line.hasPrefix("❌") ? Color.red : Color.primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(idx)
                        }
                    }
                    .padding(8)
                }
                .onChange(of: service.logs.count) { _, newValue in
                    guard newValue > 0 else { return }
                    proxy.scrollTo(newValue - 1, anchor: .bottom)
                }
            }
        }
    }

    // MARK: - 底部

    private var footer: some View {
        HStack(spacing: 12) {
            Button {
                chooseOutputDir()
            } label: {
                Label(outputDir.lastPathComponent, systemImage: "folder")
            }
            .help(outputDir.path)

            if service.isBusy {
                Text(service.currentFile.isEmpty ? "准备中…" : service.currentFile)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text(ByteCountFormatter.string(fromByteCount: service.progressBytes, countStyle: .file))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if let ipa = service.lastIPA {
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([ipa])
                } label: {
                    Label("显示 \(ipa.lastPathComponent)", systemImage: "checkmark.seal")
                }
            }

            Button {
                if let app = selection { startDump(app) }
            } label: {
                Label("开始砸壳", systemImage: "hammer.fill")
                    .frame(minWidth: 90)
            }
            .keyboardShortcut(.return, modifiers: .command)
            .buttonStyle(.borderedProminent)
            .disabled(selection == nil || service.isBusy)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - 动作

    private func startDump(_ app: AppItem) {
        selection = app
        service.startDump(app: app, outputDir: outputDir)
    }

    private func chooseOutputDir() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        panel.prompt = "选择输出目录"
        panel.directoryURL = outputDir
        if panel.runModal() == .OK, let url = panel.url {
            outputDir = url
        }
    }
}

#Preview {
    ContentView()
}

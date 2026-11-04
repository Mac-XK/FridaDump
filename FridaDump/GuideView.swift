import SwiftUI

struct DiagnoseItem: Identifiable {
    let id = UUID()
    let title: String
    let ok: Bool
    let detail: String
    let fix: String
}

struct GuideView: View {
    @ObservedObject var service: FridaService
    var onDone: () -> Void
    @State private var checks: [DiagnoseItem] = []
    @State private var checking = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "book.closed.fill").foregroundStyle(.tint)
                Text("使用说明与环境自检").font(.headline)
                Spacer()
                Button("开始使用") { onDone() }.keyboardShortcut(.defaultAction)
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    section("① 环境自检") {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(checks) { item in
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: item.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                        .foregroundStyle(item.ok ? .green : .red)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.title).font(.system(size: 12, weight: .semibold))
                                        Text(item.detail).font(.system(size: 11)).foregroundStyle(.secondary)
                                        if !item.ok {
                                            Text("→ \(item.fix)")
                                                .font(.system(size: 11))
                                                .foregroundStyle(.orange)
                                        }
                                    }
                                }
                            }
                            Button {
                                runChecks()
                            } label: {
                                Label(checking ? "检测中…" : "重新检测", systemImage: "stethoscope")
                            }
                            .disabled(checking)
                        }
                    }

                    section("② 手机端必须满足") {
                        bullet("iPhone 已 **越狱**（Dopamine / unc0ver / checkra1n / palera1n 均可，rootless 与 rootful 都支持）")
                        bullet("已安装并运行 **frida-server**，版本必须与 App 内置的 frida-core 一致：**17.25.2**")
                        bullet("用数据线连接 Mac，手机上点「信任此电脑」")
                        code("""
                        # Sileo 源：https://build.frida.re  然后
                        apt install re.frida.server
                        # rootless 路径：/var/jb/usr/sbin/frida-server
                        # rootful  路径：/usr/sbin/frida-server
                        """)
                    }

                    section("③ 常见故障对照") {
                        table()
                    }

                    section("④ 怎么用") {
                        bullet("左侧列表选中 App → 点右下「开始砸壳」（或双击）")
                        bullet("输出目录在左下角，默认 Downloads，可点它切换")
                        bullet("完成后按钮变成「显示 xxx.ipa」，可直接在 Finder 打开")
                        bullet("命令行：`FridaDump --dump <BundleID> --out <目录>`")
                    }
                }
                .padding(20)
            }
        }
        .frame(minWidth: 720, minHeight: 640)
        .onAppear(perform: runChecks)
    }

    // MARK: - 组件

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 14, weight: .bold))
            content()
        }
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("•").foregroundStyle(.secondary)
            Text(.init(text)).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func code(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11, design: .monospaced))
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func table() -> some View {
        VStack(alignment: .leading, spacing: 6) {
            row("列表空的 / 报 “DeveloperDiskImage”", "frida-server 会话失效：`killall frida-server`，launchd 会自动拉起")
            row("一直卡在“正在启动”", "frida-server 版本与 App 不一致，或目标 App 有反调试")
            row("找不到设备", "换 USB 口/数据线，重新点“信任此电脑”，先打开一次 iTunes/Finder 确认能读到手机")
            row("砸壳中途断开", "目标 App 崩溃或带反注入；换小一点的 App 先验证链路")
            row("生成的 ipa 装不上", "产物是未签名包，需要用 TrollStore / Sideloadly / 自签工具重签")
        }
    }

    private func row(_ symptom: String, _ fix: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(symptom).font(.system(size: 11, weight: .medium)).frame(width: 220, alignment: .leading)
            Text(.init(fix)).font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - 自检

    private func runChecks() {
        checking = true
        service.diagnose { items in
            checks = items
            checking = false
        }
    }
}

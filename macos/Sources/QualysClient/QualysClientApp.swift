import SwiftUI

@main
struct QualysClientApp: App {
    @State private var catalog = LiveCatalog()

    var body: some Scene {
        WindowGroup("Qualys Client") {
            CatalogView(catalog: catalog)
                .frame(minWidth: 960, minHeight: 540)
                .task { catalog.loadOnce() }
        }
        .defaultSize(width: 1150, height: 720)

        Settings {
            ConnectionSettings(catalog: catalog)
        }
    }
}

struct CatalogView: View {
    let catalog: LiveCatalog
    @State private var query = ""
    @State private var days = 30
    @State private var scoped: [Finding] = []
    @State private var product = ""
    @State private var selection: Finding.ID? = nil
    @State private var showsInspector = true
    @State private var sort = [KeyPathComparator(\Finding.deviceCount, order: .reverse),
                               KeyPathComparator(\Finding.id)]

    private var findings: [Finding] { catalog.findings }
    private var products: [String] {
        Set(scoped.map(\.product)).union(product.isEmpty ? [] : [product]).sorted()
    }

    private struct Scope: Equatable {
        let revision: Int
        let days: Int
    }

    private var currentScope: Scope {
        Scope(revision: catalog.revision, days: days)
    }

    private var filtered: [Finding] {
        let terms = query.split(whereSeparator: \.isWhitespace).map(String.init)
        return scoped.filter { finding in
            guard product.isEmpty || finding.product == product else { return false }
            if terms.isEmpty { return true }
            let text = finding.searchText
            return terms.allSatisfy { text.localizedStandardContains($0) }
        }.sorted(using: sort)
    }

    var body: some View {
        let rows = filtered
        NavigationSplitView {
            List {
                Section("Catalogus") {
                    Label("Kritieke QID’s", systemImage: "list.bullet.rectangle")
                    Label("macOS", systemImage: "laptopcomputer")
                }
            }
            .listStyle(.sidebar)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                HStack {
                    Label(catalog.tag ?? "Qualys", systemImage: "network")
                        .lineLimit(1)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    SettingsLink {
                        Image(systemName: "gearshape")
                            .accessibilityLabel("Instellingen")
                    }
                    .buttonStyle(.borderless)
                    .help("Instellingen")
                }
                .padding(14)
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 185, max: 230)
        } detail: {
            VStack(spacing: 0) {
                catalogHeader(count: rows.count)
                Divider()
                if !findings.isEmpty {
                    if catalog.isLoading || catalog.failure != nil { loadStatus }
                    table(rows)
                } else {
                    catalogContent(rows)
                }
            }
            .navigationTitle("QID-catalogus")
            .searchable(text: $query, placement: .toolbar, prompt: "Zoek op QID, CVE of titel")
            .toolbar {
                ToolbarItem {
                    Button(action: catalog.refresh) {
                        Label("Ververs", systemImage: "arrow.clockwise")
                    }
                    .keyboardShortcut("r")
                    .disabled(catalog.isLoading)
                }
                ToolbarItem {
                    Button {
                        showsInspector.toggle()
                    } label: {
                        Label("Details", systemImage: "sidebar.right")
                    }
                    .help(showsInspector ? "Verberg details" : "Toon details")
                }
            }
            .inspector(isPresented: $showsInspector) {
                inspector(rows.first { $0.id == selection })
                    .inspectorColumnWidth(min: 245, ideal: 275, max: 360)
            }
        }
        .onChange(of: currentScope, initial: true) { _, scope in
            let since = scope.days > 0 ? Calendar.current.date(byAdding: .day, value: -scope.days, to: .now) : nil
            scoped = findings.compactMap { $0.scoped(platform: .macOS, since: since, severity: .critical) }
        }
        .onChange(of: rows.map(\.id)) { _, ids in
            if let selection, !ids.contains(selection) {
                self.selection = nil
            }
        }
    }

    private func catalogHeader(count: Int) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                Text("Kritieke QID’s")
                    .font(.system(size: 29, weight: .semibold))
                Text("\(count) van \(findings.count) QID’s")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                if !catalog.isLoading, catalog.failure == nil, catalog.tag != nil {
                    Text(catalog.progress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            HStack {
                Picker("Laatste gezien", selection: $days) {
                    ForEach([7, 14, 30], id: \.self) { day in
                        Text("Laatste \(day) dagen").tag(day)
                    }
                }
                .fixedSize()
                Picker("Product", selection: $product) {
                    Text("Alle").tag("")
                    ForEach(products, id: \.self) { Text($0).tag($0) }
                }
                .frame(maxWidth: 210)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 22)
        .padding(.vertical, 20)
    }

    private var loadStatus: some View {
        HStack {
            if catalog.isLoading {
                ProgressView().controlSize(.small)
                Text(catalog.progress)
                if let started = catalog.started {
                    Text(started, style: .timer)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
                Button("Stop", action: catalog.cancel)
            } else if let failure = catalog.failure {
                Label(failure, systemImage: "exclamationmark.triangle")
            }
        }
        .font(.callout)
        .padding(12)
    }

    @ViewBuilder
    private func catalogContent(_ rows: [Finding]) -> some View {
        if catalog.isLoading {
            loadStatus
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let failure = catalog.failure {
            ContentUnavailableView {
                Label("Laden mislukt", systemImage: "exclamationmark.triangle")
            } description: {
                Text(failure)
            } actions: {
                Button("Probeer opnieuw", action: catalog.refresh)
                SettingsLink { Text("Instellingen") }
            }
        } else if catalog.tag == nil {
            ContentUnavailableView {
                Label("Verbind met Qualys", systemImage: "network")
            } description: {
                Text("Stel je Qualys API-URL, inloggegevens en asset-tag in.")
            } actions: {
                SettingsLink { Text("Open instellingen") }
                Button("Laad met bewaarde instellingen", action: catalog.refresh)
            }
        } else if findings.isEmpty {
            ContentUnavailableView("Geen kritieke macOS-QID’s binnen 30 dagen", systemImage: "list.bullet.rectangle")
        } else {
            table(rows)
        }
    }

    private func table(_ rows: [Finding]) -> some View {
        Table(rows, selection: $selection, sortOrder: $sort) {
            TableColumn("QID", value: \.id) { finding in
                Text(finding.id, format: .number.grouping(.never))
                    .font(.system(.body, design: .monospaced))
            }
            .width(min: 66, ideal: 80, max: 120)
            TableColumn("Kwetsbaarheid", value: \.title)
                .width(min: 145, ideal: 310)
            TableColumn("Product", value: \.product)
                .width(min: 70, ideal: 105, max: 180)
            TableColumn("Macs", value: \.deviceCount) { finding in
                Text(finding.deviceCount, format: .number).monospacedDigit()
            }
            .width(min: 84, ideal: 94, max: 130)
            TableColumn("Ernst", value: \.rank) { finding in
                Label {
                    Text(finding.severityLabel)
                } icon: {
                    Image(systemName: "circle.fill")
                        .font(.system(size: 7))
                        .foregroundStyle(finding.severity?.color ?? .secondary)
                }
            }
            .width(min: 100, ideal: 106, max: 145)
        }
        .alternatingRowBackgrounds(.enabled)
        .overlay {
            if rows.isEmpty {
                ContentUnavailableView {
                    Label(catalog.isLoading ? "Nog geen QID’s voor deze filters" : "Geen QID’s gevonden",
                          systemImage: "magnifyingglass")
                } actions: {
                    Button("Wis zoekopdracht en filters") {
                        query = ""
                        product = ""
                        days = 30
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func inspector(_ finding: Finding?) -> some View {
        if let finding {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(finding.reference)
                            .font(.system(.subheadline, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        Text(finding.title)
                            .font(.title2.weight(.semibold))
                            .accessibilityAddTraits(.isHeader)
                            .textSelection(.enabled)
                    }
                    Divider()
                    LabeledContent("Ernst", value: finding.severityLabel)
                    LabeledContent("Product", value: finding.product)
                    LabeledContent("Macs", value: finding.deviceCount.formatted())
                    if let date = finding.lastSeen {
                        LabeledContent("Laatst gezien", value: date.formatted(date: .abbreviated, time: .omitted))
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text("CVE’s").font(.headline)
                        if finding.cves.isEmpty {
                            Text("Geen CVE gekoppeld").foregroundStyle(.secondary)
                        } else {
                            ForEach(finding.cves, id: \.self) {
                                Text($0)
                                    .font(.system(.callout, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
            }
        } else {
            ContentUnavailableView("Selecteer een QID", systemImage: "sidebar.right")
        }
    }
}

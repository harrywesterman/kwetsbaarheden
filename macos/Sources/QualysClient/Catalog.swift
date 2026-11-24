import SwiftUI

struct Finding: Identifiable {
    let id: Int
    let title: String
    let product: String
    var severity: Severity?
    let cves: [String]

    var detections: [QualysDetection] = []
    var timesFound = 0
    var lastSeen: Date?
    var searchText: String { ([reference, title, product] + cves).joined(separator: " ") }

    var rank: Int { severity?.rawValue ?? 0 }
    var severityLabel: String { severity?.label ?? "Onbekend" }
    var reference: String { "QID \(id)" }

    func scoped(platform: Platform?, since: Date?, severity: Severity?) -> Finding? {
        var result = self
        result.timesFound = 0
        result.lastSeen = nil
        var highestRank = 0
        var matched = false
        for detection in detections {
            let detectionSeverity = detection.severity ?? self.severity
            guard platform == nil || detection.platform == platform,
                  severity == nil || detectionSeverity == severity else { continue }
            if let since, !(detection.lastSeen.map { $0 >= since } ?? false) { continue }
            matched = true
            highestRank = max(highestRank, detectionSeverity?.rawValue ?? 0)
            result.timesFound += detection.timesFound
            if let date = detection.lastSeen, date > (result.lastSeen ?? .distantPast) {
                result.lastSeen = date
            }
        }
        guard matched else { return nil }
        result.severity = Severity(rawValue: highestRank)
        return result
    }
}

struct QualysDetection {
    let platform: Platform
    let severity: Severity?
    let timesFound: Int
    let lastSeen: Date?
}

enum Platform: String, CaseIterable, Identifiable {
    case macOS, windows = "Windows", linux = "Linux", other = "Overig", unknown = "Onbekend"

    var id: Self { self }

    init(os: String) {
        let name = os.lowercased()
        if name.contains("macos") || name.contains("mac os") || name.contains("os x") {
            self = .macOS
        } else if name.contains("windows") {
            self = .windows
        } else if ["linux", "ubuntu", "debian", "centos", "red hat", "fedora", "suse", "rocky", "alma"]
            .contains(where: { name.contains($0) }) {
            self = .linux
        } else {
            self = name.isEmpty || name == "unknown" ? .unknown : .other
        }
    }
}

enum Severity: Int, CaseIterable, Identifiable {
    case minimal = 1, low, medium, high, critical

    var id: Int { rawValue }
    var title: String {
        switch self {
        case .minimal: "Minimaal"
        case .low: "Laag"
        case .medium: "Gemiddeld"
        case .high: "Hoog"
        case .critical: "Kritiek"
        }
    }

    var color: Color {
        switch self {
        case .minimal: .secondary
        case .low: .blue
        case .medium: .yellow
        case .high: .orange
        case .critical: .red
        }
    }

    var label: String { "\(rawValue) · \(title)" }
}

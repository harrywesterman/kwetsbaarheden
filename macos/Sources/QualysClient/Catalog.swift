import SwiftUI

struct Finding: Identifiable {
    let id: Int
    let title: String
    let product: String
    let severity: Severity?
    let cves: [String]

    var rank: Int { severity?.rawValue ?? 0 }
    var severityLabel: String { severity?.label ?? "Onbekend" }
    var reference: String { "QID \(id)" }

    func matches(_ terms: [String]) -> Bool {
        let searchable = ([reference, title, product] + cves).joined(separator: " ")
        return terms.allSatisfy { searchable.localizedStandardContains($0) }
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

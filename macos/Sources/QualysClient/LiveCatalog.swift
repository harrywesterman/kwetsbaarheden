import Foundation
import Observation

@MainActor @Observable
final class LiveCatalog {
    private(set) var findings: [Finding] = [] {
        didSet { revision += 1 }
    }
    private(set) var revision = 0
    private var didLoad = false
    private(set) var tag: String?
    private(set) var failure: String?
    private(set) var isLoading = false
    private(set) var progress = ""
    private(set) var started: Date?
    private var request: Task<Void, Never>?

    func loadOnce() {
        guard !didLoad else { return }
        didLoad = true
        loadSaved(reportMissingConfiguration: false)
    }

    func refresh() {
        loadSaved(reportMissingConfiguration: true)
    }

    private func loadSaved(reportMissingConfiguration: Bool) {
        do {
            guard let api = try ConnectionSettings.savedAPI() else {
                if reportMissingConfiguration { failure = QualysAPI.Problem.configuration.localizedDescription }
                return
            }
            load(api)
        } catch {
            failure = error.localizedDescription
        }
    }

    func cancel() {
        request?.cancel()
        isLoading = false
        failure = "Ophalen gestopt. Ververs om opnieuw te laden."
    }

    func load(_ api: QualysAPI, reset: Bool = false) {
        didLoad = true
        request?.cancel()
        if reset { findings = [] }
        tag = api.tag
        isLoading = true
        started = .now
        failure = nil
        progress = "Verbinding maken met Qualys…"
        request = Task {
            do {
                let result = try await api.findings { message, rows in
                    guard !Task.isCancelled else { return }
                    self.progress = message
                    if let rows, !rows.isEmpty { self.findings = rows }
                }
                guard !Task.isCancelled else { return }
                findings = result
            } catch {
                guard !Task.isCancelled else { return }
                if let error = error as? URLError, error.code == .timedOut {
                    failure = "Qualys reageerde niet op tijd. \(progress)"
                } else if let error = error as? URLError {
                    failure = "Verbinding met de Qualys API mislukt (netwerkcode \(error.errorCode))."
                } else {
                    failure = error.localizedDescription
                }
            }
            isLoading = false
        }
    }
}

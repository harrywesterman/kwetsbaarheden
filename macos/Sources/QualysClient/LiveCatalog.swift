import Foundation
import Observation

@MainActor @Observable
final class LiveCatalog {
    private(set) var findings: [Finding] = []
    private(set) var tag: String?
    private(set) var failure: String?
    private(set) var isLoading = false
    private(set) var progress = ""
    private var request: Task<Void, Never>?

    func refresh() {
        do {
            guard let api = try ConnectionSettings.savedAPI() else {
                failure = QualysAPI.Problem.configuration.localizedDescription
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
        request?.cancel()
        if reset { findings = [] }
        tag = api.tag
        isLoading = true
        failure = nil
        progress = "Verbinding maken met Qualys…"
        request = Task {
            do {
                let result = try await api.findings { message, rows in
                    guard !Task.isCancelled else { return }
                    progress = message
                    if let rows { findings = rows }
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

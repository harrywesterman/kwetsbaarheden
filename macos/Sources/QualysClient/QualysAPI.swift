import Foundation

struct QualysAPI {
    let base: URL
    let username: String
    let password: String
    let tag: String

    static func endpoint(_ value: String) -> URL? {
        guard let parts = URLComponents(string: value), parts.scheme?.lowercased() == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil, ["", "/"].contains(parts.path) else { return nil }
        return parts.url
    }

    func findings(configuration: URLSessionConfiguration = .ephemeral, now: Date = .now,
                      progress: @MainActor (String, [Finding]?) -> Void) async throws -> [Finding] {
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 45
        configuration.timeoutIntervalForResource = 90
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let cutoff = Calendar.current.date(byAdding: .day, value: -30, to: now) ?? now
        let formatter = ISO8601DateFormatter()
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var assets: Set<Int> = []
        var records: [Int: [QualysDetection]] = [:]
        var rejected = 0

        var assetCursor: Int?
        repeat {
            await progress("VMDR zoekt Macs met tag \(tag)", nil)
            let page = try await assetSearch(
                session, resource: "hostasset", fields: "id,os,tags.list.TagSimple.name",
                criteria: [("tagName", "EQUALS", tag), ("os", "CONTAINS", "Mac")], cursor: assetCursor)
            assetCursor = try page.nextCursor(after: assetCursor)
            var batch: [Int] = []
            for asset in try page.root.nodes(forXPath: "data/HostAsset") {
                let names = try asset.nodes(forXPath: "tags/list/TagSimple/name").compactMap(\.stringValue)
                guard names.contains(tag), Platform(os: Self.field("os", in: asset) ?? "") == .macOS,
                      let id = Self.field("id", in: asset).flatMap(Int.init), id > 0 else {
                    rejected += 1
                    continue
                }
                if assets.insert(id).inserted { batch.append(id) }
            }

            if !batch.isEmpty {
                let allowed = Set(batch)
                var detectionCursor: Int?
                repeat {
                    await progress("VMDR zoekt recente detecties · \(assets.count) Macs gevonden", nil)
                    let page = try await assetSearch(
                        session, resource: "hostinstancevuln",
                        criteria: [("hostAssetId", batch.count == 1 ? "EQUALS" : "IN",
                                    batch.map(String.init).joined(separator: ",")),
                                   ("lastfound", "GREATER", formatter.string(from: cutoff)),
                                   ("ignored", "EQUALS", "false"), ("disabled", "EQUALS", "false")],
                        cursor: detectionCursor)
                    detectionCursor = try page.nextCursor(after: detectionCursor)
                    for item in try page.root.nodes(forXPath: "data/HostInstanceVuln") {
                        guard let host = Self.field("hostAssetId", in: item).flatMap(Int.init),
                              allowed.contains(host) else {
                            rejected += 1
                            continue
                        }
                        guard let qid = Self.field("qid", in: item).flatMap(Int.init), qid > 0,
                              let date = Self.field("lastFound", in: item) ?? Self.field("lastfound", in: item),
                              let seen = formatter.date(from: date) ?? fractional.date(from: date) else {
                            throw Problem.response
                        }
                        guard seen >= cutoff else { continue }
                        records[qid, default: []].append(QualysDetection(
                            platform: .macOS, severity: nil, hostID: host, lastSeen: seen))
                    }
                    await progress("VMDR · \(records.count) recente QID’s vóór ernstfilter", nil)
                } while detectionCursor != nil
            }
        } while assetCursor != nil

        let findings = records.map { Self.detection(id: $0.key, records: $0.value) }
        let details = try await enrich(findings, session: session) { message, partial in
            progress(message, partial?.filter { $0.severity == .critical })
        }
        let critical = details.filter { $0.severity == .critical }
        await progress("\(assets.count) bevestigde Macs · \(critical.count) kritieke QID’s", critical)
        if rejected > 0 { throw Problem.tagScope(rejected, assets.count) }
        return critical
    }

    private func assetSearch(_ session: URLSession, resource: String, fields: String? = nil,
                             criteria: [(String, String, String)], cursor: Int?) async throws -> AssetPage {
        try Task.checkCancellation()
        var request = try makeRequest(path: "/qps/rest/2.0/search/am/" + resource, parameters: fields.map { ["fields": $0] } ?? [:])
        request.httpMethod = "POST"
        request.setValue("text/xml", forHTTPHeaderField: "Content-Type")
        let root = XMLElement(name: "ServiceRequest")
        let preferences = XMLElement(name: "preferences")
        preferences.addChild(XMLElement(name: "limitResults", stringValue: "100"))
        root.addChild(preferences)
        let filters = XMLElement(name: "filters")
        var allCriteria = criteria
        if let cursor { allCriteria.append(("id", "GREATER", String(cursor))) }
        for (field, op, value) in allCriteria {
            let criterion = XMLElement(name: "Criteria", stringValue: value)
            criterion.addAttribute(XMLNode.attribute(withName: "field", stringValue: field) as! XMLNode)
            criterion.addAttribute(XMLNode.attribute(withName: "operator", stringValue: op) as! XMLNode)
            filters.addChild(criterion)
        }
        root.addChild(filters)
        request.httpBody = XMLDocument(rootElement: root).xmlData
        let (data, response) = try await session.data(for: request)
        try Self.validate(response, for: request)
        let document = try XMLDocument(data: data, options: [.nodeLoadExternalEntitiesNever])
        guard let result = document.rootElement(), result.name == "ServiceResponse" else { throw Problem.response }
        guard Self.field("responseCode", in: result) == "SUCCESS" else { throw Problem.assetSearch }
        return AssetPage(root: result)
    }

    private struct AssetPage {
        let root: XMLElement

        func nextCursor(after previous: Int?) throws -> Int? {
            guard QualysAPI.field("hasMoreRecords", in: root) == "true" else { return nil }
            guard let next = QualysAPI.field("lastId", in: root).flatMap(Int.init), next > (previous ?? 0) else {
                throw Problem.pagination
            }
            return next
        }
    }

    private static func field(_ name: String, in node: XMLNode) -> String? {
        (node as? XMLElement)?.elements(forName: name).first?.stringValue?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func enrich(_ findings: [Finding], session: URLSession,
                        progress: @MainActor (String, [Finding]?) -> Void) async throws -> [Finding] {
        var results = findings.sorted { $0.id < $1.id }
        for start in stride(from: 0, to: results.count, by: 100) {
            try Task.checkCancellation()
            await progress("Titels, producten en CVE’s ophalen · \(start) van \(results.count) QID’s", results)
            let end = min(start + 100, results.count)
            let batch = start..<end
            let ids = batch.map { String(results[$0].id) }.joined(separator: ",")
            let request = try makeRequest(path: "/api/4.0/fo/knowledge_base/vuln/",
                                          parameters: ["action": "list", "details": "Basic", "ids": ids])
            let (data, response) = try await session.data(for: request)
            try Self.validate(response, for: request)
            let document = try XMLDocument(data: data, options: [.nodeLoadExternalEntitiesNever])
            guard let root = document.rootElement() else { throw Problem.response }
            if let response = root.elements(forName: "RESPONSE").first,
               let code = Self.field("CODE", in: response).flatMap(Int.init) { throw Problem.api(code) }
            guard root.name == "KNOWLEDGE_BASE_VULN_LIST_OUTPUT",
                  let response = root.elements(forName: "RESPONSE").first else { throw Problem.response }
            guard response.elements(forName: "WARNING").isEmpty else { throw Problem.pagination }

            let positions = Dictionary(uniqueKeysWithValues: batch.map { (results[$0].id, $0) })
            for record in try response.nodes(forXPath: "VULN_LIST/VULN") {
                guard let id = Self.field("QID", in: record).flatMap(Int.init),
                      let index = positions[id] else { continue }
                let products = try Self.values("SOFTWARE_LIST/SOFTWARE/PRODUCT", in: record)
                let cves = try Self.values("CVE_LIST/CVE/ID", in: record)
                let severity = Self.field("SEVERITY_LEVEL", in: record).flatMap(Int.init)
                    .flatMap(Severity.init(rawValue:))
                let title = Self.field("TITLE", in: record) ?? ""
                results[index] = Finding(id: id, title: title.isEmpty ? "Titel niet beschikbaar" : title,
                                         product: products.isEmpty ? "Onbekend" : products.joined(separator: ", "),
                                         severity: severity, cves: cves, detections: results[index].detections)
            }
        }
        return results
    }

    private static func values(_ xpath: String, in node: XMLNode) throws -> [String] {
        let values = try node.nodes(forXPath: xpath).compactMap {
            $0.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return Set(values.filter { !$0.isEmpty }).sorted()
    }

    private static func detection(id: Int, records: [QualysDetection]) -> Finding {
        Finding(id: id, title: "Titel niet beschikbaar", product: "Onbekend",
                severity: nil, cves: [], detections: records)
    }

    private func makeRequest(path: String, parameters: [String: String]) throws -> URLRequest {
        guard var parts = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw Problem.configuration
        }
        parts.path = path
        parts.queryItems = parameters.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        // Qualys decodes query parameters as form data.
        parts.percentEncodedQuery = parts.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        guard let url = parts.url else { throw Problem.configuration }

        var request = URLRequest(url: url)
        let credential = Data("\(username):\(password)".utf8).base64EncodedString()
        request.setValue("Basic \(credential)", forHTTPHeaderField: "Authorization")
        request.setValue("Qualys Client", forHTTPHeaderField: "X-Requested-With")
        request.setValue("application/xml", forHTTPHeaderField: "Accept")
        return request
    }

    private static func validate(_ response: URLResponse, for request: URLRequest) throws {
        guard let status = (response as? HTTPURLResponse)?.statusCode else { throw Problem.response }
        guard (200..<300).contains(status) else {
            let endpoint = [request.url?.host, request.url?.path].compactMap { $0 }.joined()
            let step: String
            switch request.url?.lastPathComponent {
            case "hostasset": step = "Apparaten zoeken"
            case "hostinstancevuln": step = "Recente detecties zoeken"
            default: step = "Titels en producten ophalen"
            }
            throw Problem.http(status, step, endpoint)
        }
    }

    enum Problem: LocalizedError {
        case configuration, response, pagination, assetSearch, http(Int, String, String), api(Int), tagScope(Int, Int)
        var errorDescription: String? {
            switch self {
            case .assetSearch: return "VMDR Asset Management heeft de zoekaanvraag afgewezen."
            case .configuration: return "Vul de HTTPS-URL van de Qualys API, je inlognaam, wachtwoord en tag in."
            case .response: return "Onverwacht antwoord. Controleer of je de Qualys API-URL van je platform gebruikt."
            case .pagination: return "Qualys heeft een onvolledig antwoord gegeven. Ververs om opnieuw te proberen."
            case .tagScope(let rejected, let verified):
                return "Tagcontrole: \(verified) apparaten in Host List bevestigd. \(rejected) hostrecords geweigerd wegens een afwijkend ID of ontbrekende tag. De getoonde resultaten kunnen onvolledig zijn."
            case .http(let status, let step, let endpoint):
                let detail: String
                switch status {
                case 401, 403: detail = "Controleer je inloggegevens en API-rechten."
                case 404: detail = "Controleer de API Server URL van je Qualys-platform."
                case 429: detail = "De API-limiet is bereikt. Probeer het later opnieuw."
                default: detail = ""
                }
                return "\(step): HTTP \(status) van \(endpoint). \(detail)"

            case .api(let code): return "Qualys API-fout \(code). Controleer je API-rechten en de naam van de tag."
            }
        }
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

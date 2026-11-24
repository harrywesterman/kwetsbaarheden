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

    func findings(configuration: URLSessionConfiguration = .ephemeral,
                  progress: @MainActor (String, [Finding]?) -> Void = { _, _ in }) async throws -> [Finding] {
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 90
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let filters = ["action": "list", "use_tags": "1", "tag_set_by": "name",
                       "tag_set_include": tag, "status": "New,Active,Re-Opened,Fixed",
                       "show_igs": "1",
                       "show_results": "0", "truncation_limit": "100"]
        var cursor: Int?
        var detections: [Int: [QualysDetection]] = [:]
        var pageNumber = 0
        var pageRows: [Finding]?
        repeat {
            pageNumber += 1
            let message = pageNumber == 1
                ? "Wachten op antwoord van Qualys · eerste pagina"
                : "Detecties ophalen · pagina \(pageNumber) · \(detections.count) unieke QID’s"
            await progress(message, pageRows)
            var parameters = filters
            if let cursor {
                parameters["id_min"] = String(cursor)
            } else {
                parameters["truncation_limit"] = "25"
            }
            try Task.checkCancellation()
            let page = try await fetch(session, path: "/api/5.0/fo/asset/host/vm/detection/",
                                       parameters: parameters, root: "HOST_LIST_VM_DETECTION_OUTPUT")
            for (id, records) in page.detections {
                detections[id, default: []].append(contentsOf: records)
            }
            pageRows = detections.map { Self.detection(id: $0.key, records: $0.value) }
            if page.hasWarning {
                guard let link = page.continuation,
                      let query = URLComponents(string: link)?.queryItems,
                      let value = query.first(where: { $0.name == "id_min" })?.value,
                      let next = Int(value), next > (cursor ?? 0) else {
                    throw Problem.pagination
                }
                cursor = next
            } else {
                cursor = nil
            }
        } while cursor != nil

        let ids = detections.keys.sorted()
        var results = ids.map { Self.detection(id: $0, records: detections[$0] ?? []) }
        for start in stride(from: 0, to: ids.count, by: 100) {
            try Task.checkCancellation()
            await progress("Details ophalen · \(start) van \(ids.count) QID’s", results)
            let batch = ids[start..<min(start + 100, ids.count)]
            let page = try await fetch(session, path: "/api/2.0/fo/knowledge_base/vuln/",
                                       parameters: ["action": "list", "details": "All",
                                                    "ids": batch.map(String.init).joined(separator: ",")],
                                       root: "KNOWLEDGE_BASE_VULN_LIST_OUTPUT")
            guard !page.hasWarning else { throw Problem.pagination }
            for index in batch.indices {
                if var detail = page.findings[ids[index]] {
                    detail.detections = results[index].detections
                    results[index] = detail
                }
            }
        }
        return results
    }

    private static func detection(id: Int, records: [QualysDetection]) -> Finding {
        Finding(id: id, title: "Titel niet beschikbaar", product: "Onbekend",
                severity: nil, cves: [], detections: records)
    }

    private func fetch(_ session: URLSession, path: String, parameters: [String: String],
                       root: String) async throws -> QualysXML {
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
        let (data, response) = try await session.data(for: request)
        guard let status = (response as? HTTPURLResponse)?.statusCode else { throw Problem.response }
        guard (200..<300).contains(status) else { throw Problem.http(status) }

        let output = QualysXML()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = output
        guard parser.parse() else { throw Problem.response }
        if let code = output.errorCode { throw Problem.api(code) }
        guard output.root == root, output.hasResponse else { throw Problem.response }
        return output
    }

    enum Problem: LocalizedError {
        case configuration, response, pagination, http(Int), api(Int)
        var errorDescription: String? {
            switch self {
            case .configuration: "Vul de HTTPS-URL van de Qualys API, je inlognaam, wachtwoord en tag in."
            case .response: "Onverwacht antwoord. Controleer of je de Qualys API-URL van je platform gebruikt."
            case .pagination: "Qualys heeft een onvolledig antwoord gegeven. Ververs om opnieuw te proberen."
            case .http(401), .http(403): "Toegang geweigerd. Controleer je inloggegevens en de VM/VMDR API-rechten."
            case .http(429): "Qualys heeft de API-limiet bereikt. Probeer het later opnieuw."
            case .http(let status): "Qualys API gaf HTTP \(status) terug."
            case .api(let code): "Qualys API-fout \(code). Controleer je API-rechten en de naam van de tag."
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

private final class QualysXML: NSObject, XMLParserDelegate {
    private var path: [String] = []
    private var value = ""
    private var id: Int?
    private var severity: Int?
    private var title = ""
    private var platform = Platform.unknown
    private var timesFound = 0
    private var lastSeen: Date?
    private let dateFormat = ISO8601DateFormatter()
    private let fractionalDateFormat: ISO8601DateFormatter = {
        let format = ISO8601DateFormatter()
        format.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return format
    }()
    private var products: Set<String> = []
    private var cves: Set<String> = []

    private(set) var root: String?
    private(set) var hasResponse = false
    private(set) var errorCode: Int?
    private(set) var hasWarning = false
    private(set) var continuation: String?
    private(set) var detections: [Int: [QualysDetection]] = [:]
    private(set) var findings: [Int: Finding] = [:]

    func parser(_ parser: XMLParser, didStartElement element: String, namespaceURI: String?,
                qualifiedName: String?, attributes: [String: String]) {
        if path.isEmpty { root = element }
        if path.count == 1, element == "RESPONSE" { hasResponse = true }
        path.append(element)
        value = ""
        if element == "HOST" { platform = .unknown }
        if element == "DETECTION" || element == "VULN" {
            id = nil
            severity = nil
            timesFound = 0
            lastSeen = nil
            title = ""
            products.removeAll()
            cves.removeAll()
        }
        if element == "WARNING" { hasWarning = true }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) { value += string }
    func parser(_ parser: XMLParser, foundCDATA data: Data) { value += String(decoding: data, as: UTF8.self) }

    func parser(_ parser: XMLParser, didEndElement element: String, namespaceURI: String?, qualifiedName: String?) {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        _ = path.popLast()
        switch (path.last, element) {
        case ("DETECTION", "QID"), ("VULN", "QID"): id = Int(text)
        case ("DETECTION", "SEVERITY"), ("VULN", "SEVERITY_LEVEL"): severity = Int(text)
        case ("HOST", "OS"): platform = Platform(os: text)
        case ("DETECTION", "TIMES_FOUND"): timesFound = max(0, Int(text) ?? 0)
        case ("DETECTION", "LAST_FOUND_DATETIME"):
            lastSeen = dateFormat.date(from: text) ?? fractionalDateFormat.date(from: text)
        case ("VULN", "TITLE"): title = text
        case ("SOFTWARE", "PRODUCT"): if !text.isEmpty { products.insert(text) }
        case ("CVE", "ID"): if !text.isEmpty { cves.insert(text) }
        case ("DETECTION_LIST", "DETECTION"):
            if let id {
                detections[id, default: []].append(QualysDetection(
                    platform: platform, severity: severity.flatMap(Severity.init(rawValue:)),
                    timesFound: timesFound, lastSeen: lastSeen))
            }
        case ("VULN_LIST", "VULN"):
            if let id {
                findings[id] = Finding(id: id, title: title.isEmpty ? "Titel niet beschikbaar" : title,
                                       product: products.isEmpty ? "Onbekend" : products.sorted().joined(separator: ", "),
                                       severity: severity.flatMap(Severity.init(rawValue:)), cves: cves.sorted())
            }
        case ("WARNING", "URL"): continuation = text
        case ("RESPONSE", "CODE"): errorCode = Int(text)
        default: break
        }
        value = ""
    }
}

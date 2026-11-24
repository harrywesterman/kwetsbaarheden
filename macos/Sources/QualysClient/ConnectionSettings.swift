import Security
import SwiftUI

struct ConnectionSettings: View {
    let catalog: LiveCatalog
    @AppStorage("qualysURL") private var savedURL = ""
    @AppStorage("qualysUsername") private var savedUsername = ""
    @AppStorage("qualysTag") private var savedTag = ""

    @State private var url = ""
    @State private var username = ""
    @State private var password = ""
    @State private var tag = ""
    @State private var feedback = ""
    @State private var hasError = false
    @State private var canSave = false

    var body: some View {
        Form {
            Section {
                TextField("Qualys-URL", text: $url, prompt: Text("https://qualysapi.example.com"))
                TextField("Inlognaam", text: $username)
                SecureField("Wachtwoord", text: $password)
                TextField("Tag", text: $tag, prompt: Text("Bijv. Werkplekken"))
            } header: {
                Label("Qualys-verbinding", systemImage: "network")
            } footer: {
                Text("Gebruik de API-URL van je Qualys-platform en de exacte naam van één asset-tag.")
            }
            HStack {
                Text(feedback)
                    .foregroundStyle(hasError ? Color.red : Color.secondary)
                Spacer()
                Button("Bewaar en laad QID’s", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
        .onAppear(perform: load)
    }

    private func load() {
        url = savedURL
        username = savedUsername
        tag = savedTag
        feedback = ""
        hasError = false
        var result: CFTypeRef?
        var query = Self.keychainItem
        query[kSecReturnData as String] = true
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        canSave = status == errSecSuccess || status == errSecItemNotFound
        if !canSave {
            showError("De sleutelhanger kon niet worden gelezen.", status: status)
        }
        password = (result as? Data).flatMap { String(data: $0, encoding: .utf8) } ?? ""
    }

    private func save() {
        let cleanedURL = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanedUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanedTag = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let endpoint = QualysAPI.endpoint(cleanedURL),
              !cleanedUsername.isEmpty, !cleanedUsername.contains(":"),
              !password.isEmpty, !cleanedTag.isEmpty, !cleanedTag.contains(",") else {
            hasError = true
            feedback = "Vul de API-URL, inlognaam, wachtwoord en één tagnaam in."
            return
        }

        let status = Self.savePassword(password)
        guard status == errSecSuccess else {
            showError("Bewaren in de sleutelhanger is mislukt.", status: status)
            return
        }
        savedURL = cleanedURL
        savedUsername = cleanedUsername
        savedTag = cleanedTag
        url = savedURL
        username = savedUsername
        tag = savedTag
        hasError = false
        feedback = "Bewaard. Volg het laden in de QID-catalogus."
        catalog.load(QualysAPI(base: endpoint, username: cleanedUsername, password: password, tag: cleanedTag), reset: true)
    }

    private func showError(_ message: String, status: OSStatus) {
        hasError = true
        feedback = "\(message) (\(status))"
    }

    static func savedAPI() throws -> QualysAPI? {
        let defaults = UserDefaults.standard
        guard let url = defaults.string(forKey: "qualysURL"), let endpoint = QualysAPI.endpoint(url),
              let username = defaults.string(forKey: "qualysUsername"), !username.isEmpty, !username.contains(":"),
              let tag = defaults.string(forKey: "qualysTag"), !tag.isEmpty, !tag.contains(",") else { return nil }
        var result: CFTypeRef?
        var query = keychainItem
        query[kSecReturnData as String] = true
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "De sleutelhanger kon niet worden gelezen (\(status))."])
        }
        guard let data = result as? Data, let password = String(data: data, encoding: .utf8),
              !password.isEmpty else { return nil }
        return QualysAPI(base: endpoint, username: username, password: password, tag: tag)
    }

    private static let keychainItem: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "nl.werkplekupdates.qualys-client",
        kSecAttrAccount as String: "qualys-connection"
    ]

    private static func savePassword(_ password: String) -> OSStatus {
        let attributes = [kSecValueData as String: Data(password.utf8)]
        let status = SecItemUpdate(keychainItem as CFDictionary, attributes as CFDictionary)
        guard status == errSecItemNotFound else { return status }
        return SecItemAdd(keychainItem.merging(attributes) { _, value in value } as CFDictionary, nil)
    }
}

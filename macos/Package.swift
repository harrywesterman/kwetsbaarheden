// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "QualysClient",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "QualysClient", targets: ["QualysClient"])],
    targets: [.executableTarget(name: "QualysClient")]
)

// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ChromeTracker",
    platforms: [.macOS(.v12)],
    products: [
        .executable(name: "ChromeTracker", targets: ["ChromeTracker"])
    ],
    targets: [
        .executableTarget(
            name: "ChromeTracker"
        )
    ]
)

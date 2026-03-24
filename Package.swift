// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "container-sandbox",
    platforms: [.macOS("15")],
    dependencies: [
        .package(url: "https://github.com/apple/container.git", from: "0.10.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "sandbox",
            dependencies: [
                .product(name: "ContainerAPIClient", package: "container"),
                .product(name: "ContainerBuild", package: "container"),
                .product(name: "ContainerPlugin", package: "container"),
                .product(name: "TerminalProgress", package: "container"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/ContainerSandbox"
        ),
        .testTarget(
            name: "ContainerSandboxTests",
            dependencies: ["sandbox"],
            path: "Tests/ContainerSandboxTests"
        ),
    ]
)

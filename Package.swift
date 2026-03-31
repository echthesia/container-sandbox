// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "container-sandbox",
    platforms: [.macOS("26")],
    dependencies: [
        .package(url: "https://github.com/apple/container.git", from: "0.10.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.80.0"),
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
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
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

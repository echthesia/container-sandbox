// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "container-sandbox",
    platforms: [.macOS("26")],
    dependencies: [
        // apple/container is pre-1.0 and minor bumps have broken API in the past;
        // pin to next minor (>=0.12.1, <0.13) until upstream stabilizes.
        .package(url: "https://github.com/apple/container.git", .upToNextMinor(from: "0.12.1")),
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

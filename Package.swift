// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "SecurityToolkit",
    platforms: [
        .iOS(.v12),
    ],
    products: [
        .library(
            name: "SecurityToolkit",
            targets: ["SecurityToolkit"]
        ),
    ],
    targets: [
        .target(
            name: "SecurityToolkit"
        )
    ]
)

// swift-tools-version:5.9
// Runs OmnipodKit's own Omnipod 5 code (the phone side) on fixed inputs and
// prints what it computes as a C header, so the pod's C port can be checked
// against the controller it has to talk to. See gen.sh.
import PackageDescription

let package = Package(
    name: "o5golden",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift", "1.4.1"..<"2.0.0"),
    ],
    targets: [
        .executableTarget(name: "o5golden", dependencies: ["CryptoSwift"], path: "Sources/o5golden"),
    ]
)

# Mobile Security Toolkit

<img src="./docs/1.png" width=300  alt="screenshot"/>

In a world where mobile devices hold vast amounts of personal and 
business-critical data, security is no longer optional — it's essential.

Security Suite is an open-source project designed to work on mobile security by 
providing a developer-friendly, all-in-one repository for developers and 
security experts.

## Features

Already implemented Features are:
- [x] Jailbreak or Root Detection
- [x] Hooks Detection
- [x] Simulator Detection

You can see them in action with the [Example App](./SecurityToolkitExample) we've provided

## Installation

You can use the Mobile Security Toolkit in your project by importing it with 
Swift Package Manager

### SPM

`.package(url: "https://github.com/EXXETA/iOS-Security-Toolkit.git", from: 
"1.0.0")`

## Usage

### Variable API

Use the gettable variables to get current status of the device:

- `ThreatDetectionCenter.areRootPrivilegesDetected: Bool`
- `ThreatDetectionCenter.areHooksDetected: Bool`
- `ThreatDetectionCenter.isSimulatorDetected: Bool`

### Async Stream API

Use Async Stream API to get detected threats asynchronously:

- `ThreatDetectionCenter.threats: AsyncStream<Threat>`

## Roadmap

Next features to be implemented:
- [ ] App Signature Check
- [ ] Debugger Detection
- [ ] Device Passcode Check
- [ ] Integrity Check
- [ ] Hardware Security Check

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md)

## Authors and acknowledgment

Authors:
- Yessine Choura
- Denis Dobanda

Special Thanks:
- Sabrina Geiger
- Dennis Gill
- Jonas Rottmann

## License

See [LICENSE](./LICENSE.md)

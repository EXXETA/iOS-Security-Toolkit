import Foundation
import SecurityToolkit

struct ThreatOverview: Hashable {
    let title: String
    let description: String
    let status: ThreatStatus
    var isOk: Bool {
        get { status == .notChecked || status == .notPresent }
    }
    
    static func threats(threatsReport: ThreatReport) -> [ThreatOverview] {
        [
            ThreatOverview(
                title: R.string.localizable.threatJailbreakTitle(),
                description: R.string.localizable.threatJailbreakDescription(),
                status: threatsReport.rootPrivileges
            ),
            ThreatOverview(
                title: R.string.localizable.threatHooksTitle(),
                description: R.string.localizable.threatHooksDescription(),
                status: threatsReport.hooks
            ),
            ThreatOverview(
                title: R.string.localizable.threatSimulatorTitle(),
                description: R.string.localizable.threatSimulatorDescription(),
                status: threatsReport.simulator
            ),
            ThreatOverview(
                title: R.string.localizable.threatDebuggerTitle(),
                description: R.string.localizable.threatDebuggerDescription(),
                status: threatsReport.debugger
            ),
            ThreatOverview(
                title: R.string.localizable.threatPasscodeUnprotectedDeviceTitle(),
                description: R.string.localizable.threatPasscodeUnprotectedDeviceDescription(),
                status: threatsReport.devicePasscode
            ),
            ThreatOverview(
                title: R.string.localizable.threatHardwareTitle(),
                description: R.string.localizable.threatHardwareDescription(),
                status: threatsReport.hardwareCryptography
            ),
        ]
    }
}



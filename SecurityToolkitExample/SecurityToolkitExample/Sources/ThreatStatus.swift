import Foundation
import SecurityToolkit

struct ThreatStatus: Hashable {
    let title: String
    let description: String
    let isDetected: Bool
    
    static let threats = [
        ThreatStatus(
            title: R.string.localizable.threatJailbreakTitle(),
            description: R.string.localizable.threatJailbreakDescription(),
            isDetected: ThreatDetectionCenter.areRootPrivilegesDetected
        ),
        ThreatStatus(
            title: R.string.localizable.threatHooksTitle(),
            description: R.string.localizable.threatHooksDescription(),
            isDetected: ThreatDetectionCenter.areHooksDetected
        ),
        ThreatStatus(
            title: R.string.localizable.threatSimulatorTitle(),
            description: R.string.localizable.threatSimulatorDescription(),
            isDetected: ThreatDetectionCenter.isSimulatorDetected
        ),
        ThreatStatus(
            title: R.string.localizable.threatDebuggerTitle(),
            description: R.string.localizable.threatDebuggerDescription(),
            isDetected: ThreatDetectionCenter.isDebuggerDetected ?? false
        ),
        ThreatStatus(
            title: R.string.localizable.threatUnprotectedDeviceTitle(),
            description: R.string.localizable.threatUnprotectedDeviceDescription(),
            isDetected: ThreatDetectionCenter.isUnprotectedDeviceDetected
        ),
    ]
}



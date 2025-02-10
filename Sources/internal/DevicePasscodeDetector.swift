import Foundation
import LocalAuthentication

// MARK: - Internal
internal final class DevicePasscodeDetector {
    
    static func threatDetected() -> ThreatStatus {
        hasDevicePasscode()
    }
}

// MARK: - Private
fileprivate extension DevicePasscodeDetector {
    
    /// Will check if the user can perform authentication with a biometrics or
    /// a passcode
    private static func hasDevicePasscode() -> ThreatStatus {
        var error: NSError?
        let result = LAContext().canEvaluatePolicy(
            .deviceOwnerAuthentication,
            error: &error
        )
        if result {
            return .notPresent
        } else if let error {
            if error.code != LAError.passcodeNotSet.rawValue {
                return .exception(
                    ThreatDetectionException.checkNotPossible(
                        "Unexpected LAError: \(error.localizedDescription)"
                    )
                )
            } else {
                return .present
            }
        } else {
            return .present
        }
    }
}

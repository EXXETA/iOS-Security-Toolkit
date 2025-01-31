import Foundation
import LocalAuthentication

// MARK: - Internal
internal final class DevicePasscodeDetection {
    
    static func threatDetected() -> Bool {
        !hasDevicePasscode()
    }
}

// MARK: - Private
fileprivate extension DevicePasscodeDetection {
    
    /// Will check if the user can perform authentication with a biometrics or
    /// a passcode
    private static func hasDevicePasscode() -> Bool {
        var error: NSError?
        let result = LAContext().canEvaluatePolicy(
            .deviceOwnerAuthentication,
            error: &error
        )
        if result {
            return true
        } else if let error {
            return error.code != LAError.passcodeNotSet.rawValue
        } else {
            return false
        }
    }
}

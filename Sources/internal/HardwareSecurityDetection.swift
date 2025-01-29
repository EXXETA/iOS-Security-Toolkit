import Foundation
import LocalAuthentication

// MARK: - Internal
internal final class HardwareSecurityDetection {
    
    static func threatDetected() -> Bool {
        !isSecureEnclaveAvailable()
    }
}

// MARK: - Private
fileprivate extension HardwareSecurityDetection {
    
    /// See https://stackoverflow.com/a/49318485/7484013
    private static func isSecureEnclaveAvailable() -> Bool {
        var error: NSError?

        /// Policies can have certain requirements which, when not satisfied,
        /// would always cause the policy evaluation to fail - e.g. a passcode
        /// set, a fingerprint enrolled with Touch ID or a face set up with
        /// Face ID. This method allows easy checking for such conditions.
        let result = LAContext().canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )
        if result {
            return true
        } else if let e = error {
            if #available(iOS 11, *) {
                return e.code != LAError.biometryNotAvailable.rawValue
            } else {
                return e.code != LAError.touchIDNotAvailable.rawValue
            }
        } else {
            return false
        }
    }
}

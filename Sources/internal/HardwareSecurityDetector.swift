import Foundation
import LocalAuthentication

// MARK: - Internal
internal final class HardwareSecurityDetector {
    
    static func threatDetected() -> ThreatStatus {
        isSecureEnclaveAvailable()
    }
}

// MARK: - Private
fileprivate extension HardwareSecurityDetector {
    
    /// See https://stackoverflow.com/a/49318485/7484013
    private static func isSecureEnclaveAvailable() -> ThreatStatus {
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
            return .notPresent
        } else if let error {
            if error.code != LAError.biometryNotAvailable.rawValue {
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

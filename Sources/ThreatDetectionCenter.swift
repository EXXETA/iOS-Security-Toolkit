import Foundation

public final class ThreatDetectionCenter {

    /// Will check if jailbreak is present
    ///
    /// - Returns:
    ///  `true`, if device is / was jailbroken;
    ///  `false` otherwise
    ///
    /// More about jailbreak: https://wikipedia.org/wiki/Jailbreak_%28iOS%29
    ///
    /// ## Notes
    /// Should also detect jailbreak, even if the device is in a "safe" mode or
    /// jailbreak mode is not active / was not properly removed
    public static var areRootPrivilegesDetected: Bool {
        JailbreakDetection.threatDetected()
    }

    /// Will check for an injection tool like Frida
    ///
    /// - Returns:
    ///  `true`, if dynamic hooks are loaded at the time;
    ///  `false` otherwise
    ///
    /// More: https://fingerprint.com/blog/exploring-frida-dynamic-instrumentation-tool-kit/
    ///
    /// ## Notes
    /// By the nature of dynamic hooks, this checks should be made on a regular
    /// basis, given the attacker may chose to hook a function at a later time
    /// after the app started
    ///
    /// !Important: with a sufficient reverse engineering skills, this check can
    /// be disabled. Use always in combination with another threats detections.
    public static var areHooksDetected: Bool {
        HooksDetection.threatDetected()
    }

    /// Will check, if the app runs in a emulated / simulated environment
    ///
    /// - Returns:
    ///  `true`, if simulator environment is detected;
    ///  `false` otherwise
    public static var isSimulatorDetected: Bool {
        SimulatorDetection.threatDetected()
    }
    
    /// Will check, if the application is being traced by a debugger.
    ///
    /// - Returns:
    ///   `true`, if a debugger is detected;
    ///   `false`, if no debugger is detected;
    ///   `nil`, if the detection process did not produce a definitive result.
    ///   This could happen due to system limitations, lack of required
    ///   permissions, or other undefined conditions.
    ///
    /// A debugger is a tool that allows developers to inspect and modify the
    /// execution of a program in real-time, potentially exposing sensitive data
    /// or allowing unauthorized control.
    ///
    /// ## Notes
    /// Please note that Apple itself may require a debugger for the app review
    /// process.
    public static var isDebuggerDetected: Bool? {
        DebuggerDetection.threatDetected()
    }

    /// Will check, if current device is protected with at least a passcode
    ///
    /// - Returns:
    ///  `true`: if device is unprotected;
    ///  `false`: if device is protected with at least a passcode
    public static var isUnprotectedDeviceDetected: Bool {
        DevicePasscodeDetection.threatDetected()
    }
    
	
	// MARK: - Async Threat Detection
	
	/// Defines all possible threats, that can be reported via the stream
    public enum Threat: String {
        case rootPrivileges
        case hooks
        case simulator
        case debugger
        case unprotectedDevice
    }
	
	/// Stream that contains possible threats that could be detected
    public static var threats: AsyncStream<Threat> {
        AsyncStream<Threat> { continuation in
            
            if JailbreakDetection.threatDetected() {
                continuation.yield(.rootPrivileges)
            }
            
            if HooksDetection.threatDetected() {
                continuation.yield(.hooks)
            }
            
            if SimulatorDetection.threatDetected() {
                continuation.yield(.simulator)
            }
            
            if DebuggerDetection.threatDetected() ?? false {
                continuation.yield(.debugger)
            }

            if DevicePasscodeDetection.threatDetected() {
                continuation.yield(.unprotectedDevice)
            }

            continuation.finish()
        }
    }
}

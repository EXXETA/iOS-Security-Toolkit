import Foundation

public final class ThreatDetectionCenter {
    
    public static var areRootPrivilegesDetected: Bool {
        JailbreakDetection.threatDetected()
    }
    
    public static var areHooksDetected: Bool {
        HooksDetection.threatDetected()
    }
    
    public static var isSimulatorDetected: Bool {
        SimulatorDetection.threatDetected()
    }
    
    /// Will check if your application is being traced by a debugger.
    ///
    /// - Returns:
    ///   `true`: If a debugger is detected.
    ///   `false`: If no debugger is detected.
    ///   `nil`: The detection process did not produce a definitive result. This could happen due to system limitations, lack of required permissions, or other undefined conditions.
    ///
    /// A debugger is a tool that allows developers to inspect and modify the execution of a program in real-time, potentially exposing sensitive data or allowing unauthorized control.
    ///
    /// ## Notes
    /// Please note that Apple itself may require a debugger for the app review process.
    public static var isDebuggerDetected: Bool? {
        DebuggerDetection.threatDetected()
    }
    
	
	// MARK: - Async Threat Detection
	
	/// Defines all possible threats, that can be reported via the stream
    public enum Threat: String {
        case rootPrivileges
        case hooks
        case simulator
        case debugger
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
            
            continuation.finish()
        }
    }
}

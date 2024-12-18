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
    
    /// Checks whether your application is being traced by a debugger.
    ///
    /// A debugger is a tool that allows developers to inspect and modify the execution of a program in real-time, potentially exposing sensitive data or allowing unauthorized control.
    ///
    /// Please note that Apple itself uses a debugger during a review and you could prevent Apple from carrying out a complete review. Which Apple will certainly not like.
    public static var isDebuggerAttached: Bool {
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
            
            if DebuggerDetection.threatDetected() {
                continuation.yield(.debugger)
            }
            
            continuation.finish()
        }
    }
}

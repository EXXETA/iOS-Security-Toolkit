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
    
	
	// MARK: - Async Threat Detection
	
	/// Defines all possible threats, that can be reported via the stream
    public enum Threat: String {
        case rootPrivileges
        case hooks
        case simulator
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
            
            continuation.finish()
        }
    }
}

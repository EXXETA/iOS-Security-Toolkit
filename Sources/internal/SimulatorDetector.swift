import Foundation

// MARK: - Internal
internal final class SimulatorDetector {
    
    static func threatDetected() -> ThreatStatus {
        let check = runsInSimulator()
        return check ? .present : .notPresent
    }
}

// MARK: - Private
fileprivate extension SimulatorDetector {
    
    /// Check if the app is running in a simulator
    static func runsInSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        if ProcessInfo.processInfo.environment["SIMULATOR_UDID"] != nil {
            return true
        }
        return false
        #endif
    }
}

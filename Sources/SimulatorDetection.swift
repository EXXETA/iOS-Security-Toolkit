import Foundation

// MARK: - Internal
internal final class SimulatorDetection {
    
    static func threatDetected() -> Bool {
        runsInSimulator()
    }
}

// MARK: - Private
fileprivate extension SimulatorDetection {
    
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

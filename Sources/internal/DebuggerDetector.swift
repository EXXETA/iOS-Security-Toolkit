import Foundation

// MARK: - Internal
internal final class DebuggerDetector {
    
    static func threatDetected() -> ThreatStatus {
        do {
            let check = try hasTracerFlagSet()
            return check ? .present : .notPresent
        } catch let e {
            let ex = e as? ThreatDetectionException
                ?? ThreatDetectionException.checkNotPossible(e.localizedDescription)
            return .exception(ex)
        }
    }
}

// MARK: - Private
fileprivate extension DebuggerDetector {
    
    /// Check P_TRACED flag from Darwin Kernel
    /// if the process is traced
    private static func hasTracerFlagSet() throws -> Bool {
        var info = kinfo_proc()
        // Kernel info, process info, specific process by PID, get current process ID
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout.stride(ofValue: info)
        
        let unixStatusCode = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        
        if unixStatusCode != 0 {
            throw ThreatDetectionException.checkNotPossible("Unexpected unix status code")
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}

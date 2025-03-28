import Foundation

// MARK: - Internal
internal final class DebuggerDetection {
    
    static func threatDetected() -> Bool? {
        hasTracerFlagSet()
    }
}

// MARK: - Private
fileprivate extension DebuggerDetection {
    
    /// Check P_TRACED flag from Darwin Kernel
    /// if the process is traced
    private static func hasTracerFlagSet() -> Bool? {
        var info = kinfo_proc()
        // Kernel info, process info, specific process by PID, get current process ID
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout.stride(ofValue: info)
        
        let unixStatusCode = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        
        return unixStatusCode == 0 ? (info.kp_proc.p_flag & P_TRACED) != 0 : nil
    }
}

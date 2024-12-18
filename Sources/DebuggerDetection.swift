import Foundation
import Darwin

// MARK: - Internal
internal final class DebuggerDetection {
    
    static func threatDetected() -> Bool {
        hasTracerFlagSet()
    }
}

// MARK: - Private
fileprivate extension DebuggerDetection {
    
    /// Check P_TRACED flag from Darwin Kernel
    /// if the process is traced
    static func hasTracerFlagSet() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()] // Kernel info, process info, specific process by PID, get current process ID
        var size = MemoryLayout.stride(ofValue: info)
        
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        if result != 0 {
            fatalError("sysctl failed")
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}

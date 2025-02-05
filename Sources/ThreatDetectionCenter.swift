import Foundation
import Combine

public final class ThreatDetectionCenter {
    
    private init() {}
    
    /// **Seconds** to wait for cycle recheck threads before running check again
    /// > Should be positive and greater than 0, otherwise value is left unchanged
    static public var threatReportsUpdateInterval: Int {
        get { return _threatReportsUpdateInterval }
        set {
            if (newValue > 0) {
                _threatReportsUpdateInterval = newValue
            }
        }
    }
    
    
    // MARK: - Async Threat Detection
    
    // Private publisher for sending temperature updates
    static private let reportPublisher = CurrentValueSubject<ThreatReport, Never>(ThreatReport())
    
    static private var task: Task<(), Never>?
    static private var internalTasks: [Task<(), Never>] = []
    static private var _threatReportsUpdateInterval = 10
    
    /// Use this API to get ThreatReports
    ///
    /// > First access will start all Tasks and cache the result.
    /// Next calls will not start any additional Tasks. Original result
    /// will be cached and can be reused
    static public var threatReports: AnyPublisher<ThreatReport, Never> {
        task = task ?? Task {
            internalTasks.append(
                Task {
                    repeat {
                        let status = JailbreakDetector.threatDetected()
                        reportPublisher.update { $0.copy(rootPrivileges: status) }
                        await insertDelay()
                    } while !Task.isCancelled
                }
            )
            internalTasks.append(
                Task {
                    repeat {
                        let status = HooksDetector.threatDetected()
                        reportPublisher.update { $0.copy(hooks: status) }
                        await insertDelay()
                    } while !Task.isCancelled
                }
            )
            internalTasks.append(
                Task {
                    let status = SimulatorDetector.threatDetected()
                    reportPublisher.update { $0.copy(simulator: status) }
                }
            )
            internalTasks.append(
                Task {
                    repeat {
                        let status = DebuggerDetector.threatDetected()
                        reportPublisher.update { $0.copy(debugger: status) }
                        await insertDelay()
                    } while !Task.isCancelled
                }
            )
            internalTasks.append(
                Task {
                    repeat {
                        let status = DevicePasscodeDetector.threatDetected()
                        reportPublisher.update { $0.copy(devicePasscode: status) }
                        await insertDelay()
                    } while !Task.isCancelled
                }
            )
            internalTasks.append(
                Task {
                    let status = HardwareSecurityDetector.threatDetected()
                    reportPublisher.update { $0.copy(hardwareCryptography: status) }
                }
            )
        }
        return reportPublisher.eraseToAnyPublisher()
    }
    
    public static func close() {
        internalTasks.forEach { $0.cancel() }
        task?.cancel()
        internalTasks.removeAll()
        task = nil
    }
    
    // MARK: - Sync API
    
    /// Will check if jailbreak is present
    ///
    /// More about jailbreak: https://wikipedia.org/wiki/Jailbreak_%28iOS%29
    ///
    /// > Should also detect jailbreak, even if the device is in a "safe" mode or
    /// jailbreak mode is not active / was not properly removed
    @available(*, deprecated, message: "Migrate to use new threatReports async API")
    public static var rootPrivilegesStatus: ThreatStatus {
        JailbreakDetector.threatDetected()
    }
    
    /// Will check for an injection tool like Frida
    ///
    /// More: https://fingerprint.com/blog/exploring-frida-dynamic-instrumentation-tool-kit/
    ///
    /// > By the nature of dynamic hooks, this checks should be made on a regular
    /// basis, given the attacker may chose to hook a function at a later time
    /// after the app started
    ///
    /// > Important: with a sufficient reverse engineering skills, this check can
    /// be disabled. Use always in combination with another threats detections.
    @available(*, deprecated, message: "Migrate to use new threatReports async API")
    public static var hooksStatus: ThreatStatus {
        HooksDetector.threatDetected()
    }
    
    /// Will check, if the app runs in a emulated / simulated environment
    @available(*, deprecated, message: "Migrate to use new threatReports async API")
    public static var simulatorStatus: ThreatStatus {
        SimulatorDetector.threatDetected()
    }
    
    /// Will check, if the application is being traced by a debugger.
    ///
    /// A debugger is a tool that allows developers to inspect and modify the
    /// execution of a program in real-time, potentially exposing sensitive data
    /// or allowing unauthorized control.
    ///
    /// > Please note that Apple itself may require a debugger for the app review
    /// process.
    @available(*, deprecated, message: "Migrate to use new threatReports async API")
    public static var debuggerStatus: ThreatStatus {
        DebuggerDetector.threatDetected()
    }
    
    /// Will check, if current device is protected with at least a passcode
    @available(*, deprecated, message: "Migrate to use new threatReports async API")
    public static var devicePasscodeStatus: ThreatStatus {
        DevicePasscodeDetector.threatDetected()
    }
    
    /// Will check, if current device has hardware protection layer
    /// (Secure Enclave)
    ///
    /// More: https://support.apple.com/en-us/guide/security/secf020d1074/web
    ///
    /// More: https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
    ///
    /// > Should be evaluated on a real device. Should only be used as an
    /// indicator, if current device is capable of hardware protection. Does not
    /// automatically mean, that encryption operations (keys, certificates,
    /// keychain) are always backed by hardware. You should make sure, such
    /// operations are implemented correctly with hardware layer
    @available(*, deprecated, message: "Migrate to use new threatReports async API")
    public static var hardwareCryptographyStatus: ThreatStatus {
        HardwareSecurityDetector.threatDetected()
    }
    
    // MARK: - Private API
    
    static private func insertDelay() async {
        try? await Task.sleep(nanoseconds: UInt64(_threatReportsUpdateInterval) * NSEC_PER_SEC)
    }
}

fileprivate extension CurrentValueSubject where Output: Equatable {
    /// Use this function to update a value in the publisher atomically
    func update(_ callback: (Output) -> Output) {
        while true {
            let value = self.value
            let newValue = callback(value)
            if (Task.isCancelled) {
                return
            } else if value == newValue {
                return
            } else if self.value == value {
                self.value = newValue
                return
            }
        }
    }
}

import Foundation

public struct ThreatReport: Equatable, Hashable {
    public let rootPrivileges: ThreatStatus
    public let hooks: ThreatStatus
    public let simulator: ThreatStatus
    public let debugger: ThreatStatus
    public let devicePasscode: ThreatStatus
    public let hardwareCryptography: ThreatStatus
    
    public init(
        rootPrivileges: ThreatStatus = .notChecked,
        hooks: ThreatStatus = .notChecked,
        simulator: ThreatStatus = .notChecked,
        debugger: ThreatStatus = .notChecked,
        devicePasscode: ThreatStatus = .notChecked,
        hardwareCryptography: ThreatStatus = .notChecked
    ) {
        self.rootPrivileges = rootPrivileges
        self.hooks = hooks
        self.simulator = simulator
        self.debugger = debugger
        self.devicePasscode = devicePasscode
        self.hardwareCryptography = hardwareCryptography
    }
    
    func copy(
        rootPrivileges: ThreatStatus? = nil,
        hooks: ThreatStatus? = nil,
        simulator: ThreatStatus? = nil,
        debugger: ThreatStatus? = nil,
        devicePasscode: ThreatStatus? = nil,
        hardwareCryptography: ThreatStatus? = nil
    ) -> ThreatReport {
        return ThreatReport(
            rootPrivileges: rootPrivileges ?? self.rootPrivileges,
            hooks: hooks ?? self.hooks,
            simulator: simulator ?? self.simulator,
            debugger: debugger ?? self.debugger,
            devicePasscode: devicePasscode ?? self.devicePasscode,
            hardwareCryptography: hardwareCryptography ?? self.hardwareCryptography
        )
    }
}

public enum ThreatStatus: Equatable, Hashable {
    case notChecked
    case notPresent
    case present
    case exception(ThreatDetectionException)
    
    public static func ==(lhs: ThreatStatus, rhs: ThreatStatus) -> Bool {
        switch (lhs, rhs) {
        case (.notChecked, .notChecked):
            return true
        case (.notPresent, .notPresent):
            return true
        case (.present, .present):
            return true
        case (.exception(let s1), .exception(let s2)):
            return s1 == s2
        default:
            return false
        }
    }
}

public enum ThreatDetectionException: Error, Equatable, Hashable {
    case checkNotPossible(String)
}

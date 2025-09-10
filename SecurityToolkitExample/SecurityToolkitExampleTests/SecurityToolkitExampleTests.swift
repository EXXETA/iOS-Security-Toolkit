//
//  SecurityToolkitTests.swift
//  SecurityToolkitTests
//
//  Created by Dobanda, Denis on 10.09.25.
//

import Testing
import Combine
import SecurityToolkit

struct SecurityToolkitTests {
    
    @Test func testDetectedThreadsForRootPrivileges() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { confirmation in
            ThreatDetectionCenter.threatReports
                .filter{ $0.rootPrivileges != .notChecked }
                .sink { report in
                    #expect(report.rootPrivileges == .notPresent)
                    confirmation()
                }
                .store(in: &cancellable)
        }
    }
    
    @Test func testDetectedThreadsForHooks() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { confirmation in
            ThreatDetectionCenter.threatReports
                .filter{ $0.hooks != .notChecked }
                .sink { report in
                    #expect(report.hooks == .notPresent)
                    confirmation()
                }
                .store(in: &cancellable)
        }
    }
    
    @Test func testDetectedThreadsForSimulator() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { confirmation in
            ThreatDetectionCenter.threatReports
                .filter{ $0.simulator != .notChecked }
                .sink { report in
                    #expect(report.simulator == .present)
                    confirmation()
                }
                .store(in: &cancellable)
        }
    }
    
    @Test func testDetectedThreadsForDebugger() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { confirmation in
            ThreatDetectionCenter.threatReports
                .filter{ $0.debugger != .notChecked }
                .sink { report in
                    #expect(report.debugger == .present)
                    confirmation()
                }
                .store(in: &cancellable)
        }
    }
    
    @Test func testDetectedThreadsForDevicePasscode() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { confirmation in
            ThreatDetectionCenter.threatReports
                .filter{ $0.devicePasscode != .notChecked }
                .sink { report in
                    #expect(report.devicePasscode == .notPresent)
                    confirmation()
                }
                .store(in: &cancellable)
        }
    }
    
    @Test func testDetectedThreadsForHardwareCryptography() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { confirmation in
            ThreatDetectionCenter.threatReports
                .filter{ $0.hardwareCryptography != .notChecked }
                .sink { report in
                    #expect(report.hardwareCryptography == ThreatStatus.exception(ThreatDetectionException.checkNotPossible("Unexpected LAError: Biometry is not enrolled.")))
                    confirmation()
                }
                .store(in: &cancellable)
        }
    }
    
    
    @Test func testConcurentDetectedThreads() async throws {
        var cancellable: Set<AnyCancellable> = []
        await confirmation { c in
            ThreatDetectionCenter.threatReports
                .sink { _ in c()}
                .store(in: &cancellable)
        }
    
        await confirmation { c in
            ThreatDetectionCenter.threatReports
                .sink { report in
                    #expect(report.rootPrivileges == .notPresent)
                    c()
                }
                .store(in: &cancellable)
        }
    }

}

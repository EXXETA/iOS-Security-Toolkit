//
//  SecurityToolkitTests.swift
//  SecurityToolkitTests
//
//  Created by Dobanda, Denis on 10.09.25.
//

import Foundation
import Testing
import Combine
@testable import SecurityToolkit

@Suite(.serialized) struct SecurityToolkitTests {
    
    @Test func testNoDetectedThreadsAfterCancel() async throws {
        var cancellable: Set<AnyCancellable> = []
        var closed = false
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .sink { report in
                    if !closed {
                        ThreatDetectionCenter.close()
                    } else {
                        #expect(true == false, "Should never happen")
                    }
                }
                .store(in: &cancellable)

            Task {
                try? await Task.sleep(nanoseconds: UInt64(500) * NSEC_PER_MSEC)
                cont.resume()
            }
        }
    }
    
    @Test func testDetectedThreadsForRootPrivileges() async throws {
        var cancellable: Set<AnyCancellable> = []
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .filter{ $0.rootPrivileges != .notChecked }
                .sink { report in
                    ThreatDetectionCenter.close()
                    #expect(report.rootPrivileges == .notPresent)
                    cont.resume()
                }
                .store(in: &cancellable)
        }
        try? await Task.sleep(nanoseconds: UInt64(100) * NSEC_PER_MSEC)
    }
    
    @Test func testDetectedThreadsForHooks() async throws {
        var cancellable: Set<AnyCancellable> = []
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .filter{ $0.hooks != .notChecked }
                .sink { report in
                    ThreatDetectionCenter.close()
                    // as the pipeline differs to local machine
                    #expect(report.hooks != .notChecked)
                    cont.resume()
                }
                .store(in: &cancellable)
        }
        try? await Task.sleep(nanoseconds: UInt64(100) * NSEC_PER_MSEC)
    }
    
    @Test func testDetectedThreadsForSimulator() async throws {
        var cancellable: Set<AnyCancellable> = []
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .filter{ $0.simulator != .notChecked }
                .sink { report in
                    ThreatDetectionCenter.close()
                    #expect(report.simulator == .present)
                    cont.resume()
                }
                .store(in: &cancellable)
        }
        try? await Task.sleep(nanoseconds: UInt64(100) * NSEC_PER_MSEC)
    }
    
    @Test func testDetectedThreadsForDebugger() async throws {
        var cancellable: Set<AnyCancellable> = []
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .filter{ $0.debugger != .notChecked }
                .sink { report in
                    ThreatDetectionCenter.close()
                    #expect(report.debugger == .notPresent)
                    cont.resume()
                }
                .store(in: &cancellable)
        }
        try? await Task.sleep(nanoseconds: UInt64(100) * NSEC_PER_MSEC)
    }
    
    
    @Test func testDetectedThreadsForDevicePasscode() async throws {
        var cancellable: Set<AnyCancellable> = []
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .filter{ $0.devicePasscode != .notChecked }
                .sink { report in
                    ThreatDetectionCenter.close()
                    #expect(report.devicePasscode == .notPresent)
                    cont.resume()
                }
                .store(in: &cancellable)
        }
        try? await Task.sleep(nanoseconds: UInt64(100) * NSEC_PER_MSEC)
    }
    
    @Test func testDetectedThreadsForHardwareCryptography() async throws {
        var cancellable: Set<AnyCancellable> = []
        await withCheckedContinuation { cont in
            ThreatDetectionCenter.threatReports
                .filter{ $0.hardwareCryptography != .notChecked }
                .sink { report in
                    ThreatDetectionCenter.close()
                    switch (report.hardwareCryptography) {
                    case .exception(_): _ = report
                    default: #expect(report.hardwareCryptography == ThreatStatus.exception(ThreatDetectionException.checkNotPossible("")))
                    }
                    cont.resume()
                }
                .store(in: &cancellable)
        }
        try? await Task.sleep(nanoseconds: UInt64(100) * NSEC_PER_MSEC)
    }
}

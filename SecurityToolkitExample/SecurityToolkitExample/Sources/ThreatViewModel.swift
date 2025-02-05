//
//  ThreatViewModel.swift
//  SecurityToolkitExample
//
//  Created by Dobanda, Denis on 05.02.25.
//
import Foundation
import SecurityToolkit
import Combine

class ThreatViewModel: ObservableObject {
    static let shared: ThreatViewModel = ThreatViewModel()
    
    @Published var threatOverview = [ThreatOverview]()
    
    private var subscribtions = Set<AnyCancellable>()
    
    private init() {
        ThreatDetectionCenter
            .threatReports
            .receive(on: DispatchQueue.main)
            .map(ThreatOverview.threats(threatsReport:))
            .sink { self.threatOverview = $0 }
            .store(in: &subscribtions)
    }
}

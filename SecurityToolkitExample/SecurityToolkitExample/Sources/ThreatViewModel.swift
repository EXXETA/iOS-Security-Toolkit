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
    
    private init() {
        ThreatDetectionCenter
            .threatReports
            .map(ThreatOverview.threats(threatsReport:))
            .receive(on: DispatchQueue.main)
            .assign(to: &$threatOverview)
    }
}

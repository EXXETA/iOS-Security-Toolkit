import Foundation

enum SystemImage: String {
    case stethoscope 
    
    func callAsFunction() -> String {
        self.rawValue
    }
}

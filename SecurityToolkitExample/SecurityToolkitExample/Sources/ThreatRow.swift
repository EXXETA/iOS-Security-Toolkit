import SwiftUI

struct ThreatRow: View {
    
    let threat: ThreatOverview
    
    var threatText: String {
        get {
            switch threat.status {
            case .notChecked: return R.string.localizable.threatRowStateInitial()
            case .notPresent: return R.string.localizable.threatRowStateSafe()
            case .present: return R.string.localizable.threatRowStateDetected()
            case .exception: return R.string.localizable.threatRowStateException()
            }
        }
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(threat.title)
                Spacer()
                Text(threatText)
                    .font(.caption2)
                    .foregroundColor(.white)
                    .padding(.horizontal, Dimens.unit8)
                    .padding(.vertical, Dimens.unit2)
                    .background {
                        RoundedRectangle(cornerRadius: Dimens.unit4)
                            .fill(threat.isOk ? .green : .red)
                    }
            }
            Text(threat.description)
                .font(.footnote)
                .foregroundStyle(.gray)
        }
    }
}

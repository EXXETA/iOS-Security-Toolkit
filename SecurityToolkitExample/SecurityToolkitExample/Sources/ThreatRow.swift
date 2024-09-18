import SwiftUI

struct ThreatRow: View {
    
    let threat: ThreatStatus
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(threat.title)
                Spacer()
                Text(threat.isDetected ? R.string.localizable.threatRowStateDetected() : R.string.localizable.threatRowStateSafe())
                    .font(.caption2)
                    .foregroundColor(.white)
                    .padding(.horizontal, Dimens.unit8)
                    .padding(.vertical, Dimens.unit2)
                    .background {
                        RoundedRectangle(cornerRadius: Dimens.unit4)
                            .fill(threat.isDetected ? .red : .green)
                    }
            }
            Text(threat.description)
                .font(.footnote)
                .foregroundStyle(.gray)
        }
    }
}

import SwiftUI

struct ThreatList: View {
     
    var body: some View {
        List {
            Section {
                ForEach(ThreatStatus.threats, id: \.self) {
                    ThreatRow(threat: $0)
                }
            } header: {
                VStack(spacing: Dimens.unit8) {
                    Image(systemName: SystemImage.stethoscope())
                        .font(.system(size: Dimens.unit70))
                        .frame(maxWidth: .infinity)
                    Text(R.string.localizable.threatListTitle())
                        .font(.largeTitle)
                        .fontWeight(.bold)
                        .frame(maxWidth: .infinity)
                    Text(R.string.localizable.threatListDescription())
                        .multilineTextAlignment(.center)
                        .font(.body)
                        .foregroundStyle(.gray)
                        .frame(maxWidth: .infinity)
                }
                .padding(.top, Dimens.unit32)
            }
            .headerProminence(.increased)
        }
        
    }
}

#Preview {
    ThreatList()
}

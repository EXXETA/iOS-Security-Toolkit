import SwiftUI
import SecurityToolkit

struct ThreatList: View {
     
    @ObservedObject private var vm = ThreatViewModel.shared
    
    var body: some View {
        List {
            Section {
                ForEach(vm.threatOverview, id: \.self) {
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

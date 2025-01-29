import Foundation
import UIKit

// MARK: - Internal
internal final class JailbreakDetection {
    
    static func threatDetected() -> Bool {
        hasSuspiciousFiles() || hasUnexpectedFilePermissions() || canOpenSuspiciousLinks()
    }
}

// MARK: - Private
fileprivate extension JailbreakDetection {
    
    /// Check for suspicious files
    static func hasSuspiciousFiles() -> Bool {
        let suspiciousFiles = [
            "/Applications/Cydia.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/Applications/blackra1n.app",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/var/tmp/cydia.log",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/usr/sbin/frida-server",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib",
            "/var/log/syslog",
            // manually checked list for rootless palera1n jb
            "/var/jb",
            "/var/jb/.installed_dopamine",
            "/var/jb/Applications/Sileo.app",
        ]
        
        return suspiciousFiles.contains(where: FileManager.default.fileExists(atPath:))
    }
    
    /// Will try to create and remove a file in a path which should be not allowed without root access
    private static func hasUnexpectedFilePermissions() -> Bool {
        let files = ["/private/jailbreak.txt", "/var/jb/jailbreak.txt", "/private/var/jb/jailbreak.txt"]
        for file in files {
            do {
                try "Test".write(toFile: file, atomically: true, encoding: String.Encoding.utf8)
                try FileManager.default.removeItem(atPath: file)
                return true
            } catch {
                // We actually want an error to be thrown, which means we were unable to create/delete the file which makes sense
            }
        }
        return false
    }
    
    private static func canOpenSuspiciousLinks() -> Bool {
        let urls = [
            URL(string: "cydia://url/https://cydia.saurik.com/api/share#?source=https://beta.autotouch.net/")!,
            URL(string: "installer://add/repo=https://beta.autotouch.net/")!,
            URL(string: "sileo://source/https://beta.autotouch.net/")!,
            URL(string: "zbra://sources/add/https://beta.autotouch.net/")!
        ]
        return urls.contains(where: UIApplication.shared.canOpenURL)
    }
}

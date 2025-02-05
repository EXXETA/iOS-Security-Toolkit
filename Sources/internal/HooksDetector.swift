import Foundation
import MachO

// MARK: - Internal
internal final class HooksDetector {
    
    static func threatDetected() -> ThreatStatus {
        let check = hasDynamicLibrariesLoaded() || hasSuspiciousFiles() || hasOpenPorts()
        return check ? .present : .notPresent
    }
}

// MARK: - Private
fileprivate extension HooksDetector {
    
    /// Check has loaded dynamic libraries
    private static func hasDynamicLibrariesLoaded() -> Bool {
        let suspiciousLibraries: Set<String> = [
            "frida",
            "cynject",
            "libcycript"
        ]

        for index in 0..<_dyld_image_count() {
            let imageName = String(cString: _dyld_get_image_name(index))
            for library in suspiciousLibraries where imageName.lowercased().contains(library) {
                return true
            }
        }

        return false
    }

    /// Check has suspicious files
    private static func hasSuspiciousFiles() -> Bool {
        let suspiciousFiles = [
            "/usr/sbin/frida-server"
        ]
        return suspiciousFiles.contains(where: FileManager.default.fileExists(atPath:))
    }

    /// Check has open ports
    private static func hasOpenPorts() -> Bool {
        let ports = [
            27042, // Frida
            4444, // Needle
            22, // OpenSSH
            44 // checkrain
        ]
        return ports.contains(where: canOpenLocalConnection(port:))
    }

    /// Check if it can open local connection
    private static func canOpenLocalConnection(port: Int) -> Bool {
        var serverAddress = sockaddr_in()
        serverAddress.sin_family = sa_family_t(AF_INET)
        serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
        serverAddress.sin_port = Int(OSHostByteOrder()) == OSLittleEndian
        ? _OSSwapInt16(in_port_t(port))
        : in_port_t(port)
        let sock = socket(AF_INET, SOCK_STREAM, 0)

        let result = withUnsafePointer(to: &serverAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        defer {
            close(sock)
        }
        return result != -1
    }
}

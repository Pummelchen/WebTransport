import Darwin
import Foundation

public struct QUICUDPEndpoint: Equatable, Sendable {
    public var host: String
    public var port: UInt16

    public init(host: String = "127.0.0.1", port: UInt16) {
        self.host = host
        self.port = port
    }
}

public enum QUICUDPError: Error, CustomStringConvertible, Sendable {
    case posix(operation: String, code: Int32)
    case timeout
    case invalidAddress
    case invalidReceiveConfiguration(String)

    public var description: String {
        switch self {
        case .posix(let operation, let code):
            "\(operation) failed: \(String(cString: strerror(code)))"
        case .timeout:
            "UDP receive timed out"
        case .invalidAddress:
            "invalid UDP address"
        case .invalidReceiveConfiguration(let message):
            message
        }
    }
}

public final class QUICUDPPort: @unchecked Sendable {
    private static let maximumUDPDatagramBytes = 65_535

    private let descriptor: Int32
    private let receiveLock = NSLock()
    public let localEndpoint: QUICUDPEndpoint

    public init(bindPort: UInt16 = 0) throws {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            throw QUICUDPError.posix(operation: "socket", code: errno)
        }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = bindPort.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.bind(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let code = errno
            close(fd)
            throw QUICUDPError.posix(operation: "bind", code: code)
        }

        var boundAddress = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getsockname(fd, sockaddrPointer, &boundLength)
            }
        }
        guard nameResult == 0 else {
            let code = errno
            close(fd)
            throw QUICUDPError.posix(operation: "getsockname", code: code)
        }

        self.descriptor = fd
        self.localEndpoint = QUICUDPEndpoint(port: UInt16(bigEndian: boundAddress.sin_port))
    }

    deinit {
        close(descriptor)
    }

    public func send(_ data: Data, to endpoint: QUICUDPEndpoint) throws {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = endpoint.port.bigEndian
        guard endpoint.host == "127.0.0.1" else {
            throw QUICUDPError.invalidAddress
        }
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let sent = try data.withUnsafeBytes { bytes in
            try withUnsafePointer(to: &address) { pointer in
                try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    let result = sendto(
                        descriptor,
                        bytes.baseAddress,
                        data.count,
                        0,
                        sockaddrPointer,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                    guard result >= 0 else {
                        throw QUICUDPError.posix(operation: "sendto", code: errno)
                    }
                    return result
                }
            }
        }

        guard sent == data.count else {
            throw QUICUDPError.posix(operation: "sendto-short-write", code: EMSGSIZE)
        }
    }

    public func receive(maximumBytes: Int = 65_535, timeoutMilliseconds: Int32 = 1_000) throws -> (Data, QUICUDPEndpoint) {
        guard maximumBytes > 0 && maximumBytes <= Self.maximumUDPDatagramBytes else {
            throw QUICUDPError.invalidReceiveConfiguration("maximumBytes must be in 1...\(Self.maximumUDPDatagramBytes)")
        }
        guard timeoutMilliseconds >= 0 else {
            throw QUICUDPError.invalidReceiveConfiguration("timeoutMilliseconds must be non-negative")
        }

        receiveLock.lock()
        defer { receiveLock.unlock() }

        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        let pollResult = Darwin.poll(&pollDescriptor, 1, timeoutMilliseconds)
        guard pollResult > 0 else {
            if pollResult == 0 {
                throw QUICUDPError.timeout
            }
            throw QUICUDPError.posix(operation: "poll", code: errno)
        }

        var storage = sockaddr_storage()
        var storageLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        var buffer = [UInt8](repeating: 0, count: maximumBytes)
        let received = try buffer.withUnsafeMutableBytes { bytes in
            try withUnsafeMutablePointer(to: &storage) { pointer in
                try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    guard let baseAddress = bytes.baseAddress else {
                        throw QUICUDPError.invalidReceiveConfiguration("receive buffer is empty")
                    }
                    return recvfrom(descriptor, baseAddress, bytes.count, 0, sockaddrPointer, &storageLength)
                }
            }
        }
        guard received >= 0 else {
            throw QUICUDPError.posix(operation: "recvfrom", code: errno)
        }

        let endpoint = withUnsafePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { addressPointer in
                QUICUDPEndpoint(port: UInt16(bigEndian: addressPointer.pointee.sin_port))
            }
        }
        return (Data(buffer.prefix(received)), endpoint)
    }
}

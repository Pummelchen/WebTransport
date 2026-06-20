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

/// Low-level loopback UDP helper used by QUIC runtime tests and local packet
/// probes. It intentionally accepts only `localhost`, `127.0.0.1`, and `::1`;
/// production remote networking is handled by `WebTransportNetworkRuntime`.
// SAFETY: The file descriptor is immutable after bind and closed exactly once in
// `deinit`. Receive calls are serialized with `receiveLock`; send calls use
// `sendto` on the immutable descriptor and do not mutate shared Swift state.
public final class QUICUDPPort: @unchecked Sendable {
    private static let maximumUDPDatagramBytes = 65_535

    private let descriptor: Int32
    private let receiveLock = NSLock()
    public let localEndpoint: QUICUDPEndpoint

    public init(bindHost: String = "127.0.0.1", bindPort: UInt16 = 0) throws {
        let bindAddress = try Self.loopbackAddress(host: bindHost, port: bindPort)
        let fd = socket(bindAddress.family, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            throw QUICUDPError.posix(operation: "socket", code: errno)
        }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = bindAddress.storage
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.bind(fd, sockaddrPointer, bindAddress.length)
            }
        }
        guard bindResult == 0 else {
            let code = errno
            close(fd)
            throw QUICUDPError.posix(operation: "bind", code: code)
        }

        var boundAddress = sockaddr_storage()
        var boundLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
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
        self.localEndpoint = try Self.endpoint(from: boundAddress)
    }

    public convenience init(bindPort: UInt16) throws {
        try self.init(bindHost: "127.0.0.1", bindPort: bindPort)
    }

    deinit {
        close(descriptor)
    }

    public func send(_ data: Data, to endpoint: QUICUDPEndpoint) throws {
        let destination = try Self.loopbackAddress(host: endpoint.host, port: endpoint.port)
        var address = destination.storage

        let sent = try data.withUnsafeBytes { bytes in
            try withUnsafePointer(to: &address) { pointer in
                try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    let result = sendto(
                        descriptor,
                        bytes.baseAddress,
                        data.count,
                        0,
                        sockaddrPointer,
                        destination.length
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

        let endpoint = try Self.endpoint(from: storage)
        return (Data(buffer.prefix(received)), endpoint)
    }

    private struct LoopbackAddress {
        var family: Int32
        var storage: sockaddr_storage
        var length: socklen_t
    }

    private static func loopbackAddress(host: String, port: UInt16) throws -> LoopbackAddress {
        switch host {
        case "127.0.0.1", "localhost":
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else {
                throw QUICUDPError.invalidAddress
            }
            return LoopbackAddress(
                family: AF_INET,
                storage: storage(from: address),
                length: socklen_t(MemoryLayout<sockaddr_in>.size)
            )
        case "::1":
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = port.bigEndian
            guard inet_pton(AF_INET6, "::1", &address.sin6_addr) == 1 else {
                throw QUICUDPError.invalidAddress
            }
            return LoopbackAddress(
                family: AF_INET6,
                storage: storage(from: address),
                length: socklen_t(MemoryLayout<sockaddr_in6>.size)
            )
        default:
            throw QUICUDPError.invalidAddress
        }
    }

    private static func storage(from address: sockaddr_in) -> sockaddr_storage {
        var storage = sockaddr_storage()
        withUnsafeMutablePointer(to: &storage) { storagePointer in
            storagePointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
                pointer.pointee = address
            }
        }
        return storage
    }

    private static func storage(from address: sockaddr_in6) -> sockaddr_storage {
        var storage = sockaddr_storage()
        withUnsafeMutablePointer(to: &storage) { storagePointer in
            storagePointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { pointer in
                pointer.pointee = address
            }
        }
        return storage
    }

    private static func endpoint(from storage: sockaddr_storage) throws -> QUICUDPEndpoint {
        switch Int32(storage.ss_family) {
        case AF_INET:
            return try withUnsafePointer(to: storage) { pointer in
                try pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { addressPointer in
                    var address = addressPointer.pointee.sin_addr
                    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    guard inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else {
                        throw QUICUDPError.invalidAddress
                    }
                    return QUICUDPEndpoint(
                        host: Self.string(from: buffer),
                        port: UInt16(bigEndian: addressPointer.pointee.sin_port)
                    )
                }
            }
        case AF_INET6:
            return try withUnsafePointer(to: storage) { pointer in
                try pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { addressPointer in
                    var address = addressPointer.pointee.sin6_addr
                    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else {
                        throw QUICUDPError.invalidAddress
                    }
                    return QUICUDPEndpoint(
                        host: Self.string(from: buffer),
                        port: UInt16(bigEndian: addressPointer.pointee.sin6_port)
                    )
                }
            }
        default:
            throw QUICUDPError.invalidAddress
        }
    }

    private static func string(from nulTerminatedBuffer: [CChar]) -> String {
        let bytes = nulTerminatedBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}

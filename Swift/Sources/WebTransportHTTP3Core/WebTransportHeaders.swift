import Foundation
import WebTransportQUICCore

public enum WebTransportHTTP3Headers {
    public static func connectRequest(
        authority: String,
        path: String,
        scheme: String = "https",
        origin: String? = nil,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> [HTTPFieldLine] {
        guard !authority.isEmpty else {
            throw QUICCodecError.malformed("WebTransport CONNECT :authority must not be empty")
        }
        guard path.hasPrefix("/") else {
            throw QUICCodecError.malformed("WebTransport CONNECT :path must be absolute")
        }

        var fields = [
            try HTTPFieldLine(name: ":method", value: "CONNECT"),
            try HTTPFieldLine(name: ":scheme", value: scheme),
            try HTTPFieldLine(name: ":authority", value: authority),
            try HTTPFieldLine(name: ":path", value: path),
            try HTTPFieldLine(name: ":protocol", value: constants.upgradeToken)
        ]
        if let origin {
            fields.append(try HTTPFieldLine(name: "origin", value: origin))
        }
        return fields
    }

    public static func successfulResponse(status: UInt16 = 200) throws -> [HTTPFieldLine] {
        guard (200..<300).contains(status) else {
            throw QUICCodecError.malformed("WebTransport success response status must be 2xx")
        }
        return [
            try HTTPFieldLine(name: ":status", value: String(status))
        ]
    }

    public static func validateConnectRequest(_ fields: [HTTPFieldLine]) throws {
        let map = try pseudoHeaderMap(fields)
        try require(map, ":method", equals: "CONNECT")
        try require(map, ":protocol", equals: WebTransportHTTP3DraftConstants.current.upgradeToken)
        try require(map, ":scheme", equals: "https")
        try requirePresent(map, ":authority")
        try requirePresent(map, ":path")
        guard map[":path"]?.hasPrefix("/") == true else {
            throw QUICCodecError.malformed("WebTransport CONNECT :path must be absolute")
        }
    }

    public static func validateSuccessfulResponse(_ fields: [HTTPFieldLine]) throws {
        let map = try pseudoHeaderMap(fields)
        guard let status = map[":status"], let value = Int(status), (200..<300).contains(value) else {
            throw QUICCodecError.malformed("WebTransport response requires 2xx :status")
        }
    }

    public static func connectRequestHeadersFrame(
        authority: String,
        path: String,
        scheme: String = "https",
        origin: String? = nil,
        constants: WebTransportHTTP3DraftConstants = .current
    ) throws -> HTTP3Frame {
        try QPACK.headersFrame(fields: connectRequest(
            authority: authority,
            path: path,
            scheme: scheme,
            origin: origin,
            constants: constants
        ))
    }

    public static func successfulResponseHeadersFrame(status: UInt16 = 200) throws -> HTTP3Frame {
        try QPACK.headersFrame(fields: successfulResponse(status: status))
    }

    private static func pseudoHeaderMap(_ fields: [HTTPFieldLine]) throws -> [String: String] {
        var map: [String: String] = [:]
        var sawRegularHeader = false
        for field in fields {
            if field.name.hasPrefix(":") {
                guard !sawRegularHeader else {
                    throw QUICCodecError.malformed("HTTP pseudo-header appears after regular header")
                }
                guard map[field.name] == nil else {
                    throw QUICCodecError.malformed("duplicate HTTP pseudo-header")
                }
                map[field.name] = field.value
            } else {
                sawRegularHeader = true
            }
        }
        return map
    }

    private static func require(_ map: [String: String], _ key: String, equals expected: String) throws {
        guard map[key] == expected else {
            throw QUICCodecError.malformed("required pseudo-header \(key) is missing or invalid")
        }
    }

    private static func requirePresent(_ map: [String: String], _ key: String) throws {
        guard let value = map[key], !value.isEmpty else {
            throw QUICCodecError.malformed("required pseudo-header \(key) is missing")
        }
    }
}

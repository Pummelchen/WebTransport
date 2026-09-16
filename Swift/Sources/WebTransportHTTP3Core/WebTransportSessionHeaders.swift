import WebTransportQUICCore

public enum WebTransportHeaderName {
    public static let availableProtocols = "wt-available-protocols"
    public static let selectedProtocol = "wt-protocol"
}

public enum WebTransportProtocolNegotiation {
    public static func validate(_ protocols: [String]) throws {
        var seen = Set<String>()
        for name in protocols {
            guard !name.isEmpty else {
                throw QUICCodecError.malformed("WebTransport protocol token must not be empty")
            }
            guard
                name.utf8.allSatisfy({ byte in
                    byte >= 0x21 && byte <= 0x7e && byte != 0x22 && byte != 0x2c && byte != 0x5c
                })
            else {
                throw QUICCodecError.malformed("WebTransport protocol token contains invalid bytes")
            }
            guard seen.insert(name).inserted else {
                throw QUICCodecError.malformed("duplicate WebTransport protocol token")
            }
        }
    }

    public static func encodeList(_ protocols: [String]) throws -> String {
        try validate(protocols)
        return protocols.map { encodeItem($0) }.joined(separator: ", ")
    }

    public static func decodeList(_ value: String) throws -> [String] {
        var parser = StructuredFieldStringParser(value)
        let protocols = try parser.parseStringList()
        try validate(protocols)
        return protocols
    }

    public static func encodeItem(_ value: String) -> String {
        let escaped = value.flatMap { character -> [Character] in
            switch character {
            case "\"", "\\":
                return ["\\", character]
            default:
                return [character]
            }
        }
        return "\"\(String(escaped))\""
    }

    public static func decodeItem(_ value: String) throws -> String {
        var parser = StructuredFieldStringParser(value)
        let item = try parser.parseStringItem()
        try validate([item])
        return item
    }

    public static func select(requested: [String], supported: [String]) -> String? {
        guard !requested.isEmpty, !supported.isEmpty else {
            return nil
        }
        let supportedSet = Set(supported)
        return requested.first { supportedSet.contains($0) }
    }
}

enum WebTransportSessionHeaders {
    static func request(
        from fields: [HTTPFieldLine],
        acceptedProtocolTokens: Set<String> = [WebTransportHTTP3DraftConstants.current.upgradeToken]
    ) throws -> WebTransportSessionRequest {
        try WebTransportHTTP3Headers.validateConnectRequest(
            fields,
            acceptedProtocolTokens: acceptedProtocolTokens
        )
        return try WebTransportSessionRequest(
            authority: try requiredField(":authority", from: fields),
            path: try requiredField(":path", from: fields),
            origin: optionalField("origin", from: fields),
            availableProtocols: try availableProtocols(from: fields)
        )
    }

    static func status(from fields: [HTTPFieldLine]) throws -> UInt16 {
        guard let statusValue = try optionalUniqueField(":status", from: fields),
            let status = WebTransportHTTP3Headers.parseStatusCode(statusValue),
            (100...599).contains(status)
        else {
            throw QUICCodecError.malformed("WebTransport response requires a valid :status")
        }
        return status
    }

    static func selectedProtocol(from fields: [HTTPFieldLine]) throws -> String? {
        guard let value = try optionalUniqueField(WebTransportHeaderName.selectedProtocol, from: fields) else {
            return nil
        }
        // A malformed wt-protocol is a protocol error, not "no protocol
        // selected". Swallowing it left the peers disagreeing about which
        // subprotocol was negotiated: the server believes it selected one and
        // the application here believes none was chosen. For WebTransport that
        // decides application semantics, so the two sides would then speak
        // different protocols over the same session.
        return try WebTransportProtocolNegotiation.decodeItem(value)
    }

    static func selectProtocol(
        requestProtocols: [String],
        policy: WebTransportServerSessionPolicy
    ) throws -> String? {
        try WebTransportProtocolNegotiation.validate(requestProtocols)
        try WebTransportProtocolNegotiation.validate(policy.supportedProtocols)
        return WebTransportProtocolNegotiation.select(
            requested: requestProtocols,
            supported: policy.supportedProtocols
        )
    }

    static func responseFrame(status: UInt16, selectedProtocol: String? = nil) throws -> HTTP3Frame {
        guard (100...599).contains(status) else {
            throw QUICCodecError.valueOutOfRange("HTTP status must be 100...599")
        }
        var fields = [
            try HTTPFieldLine(name: ":status", value: String(status))
        ]
        if let selectedProtocol {
            try WebTransportProtocolNegotiation.validate([selectedProtocol])
            fields.append(
                try HTTPFieldLine(
                    name: WebTransportHeaderName.selectedProtocol,
                    value: WebTransportProtocolNegotiation.encodeItem(selectedProtocol)
                ))
        }
        return try QPACK.headersFrame(fields: fields)
    }

    private static func availableProtocols(from fields: [HTTPFieldLine]) throws -> [String] {
        guard let value = try optionalUniqueField(WebTransportHeaderName.availableProtocols, from: fields) else {
            return []
        }
        // As above: a peer that sent the header and got it wrong is not a peer
        // that offered nothing. An absent header means no protocols offered; a
        // malformed one is a malformed CONNECT, which is how every other
        // malformed field in this request is already treated.
        return try WebTransportProtocolNegotiation.decodeList(value)
    }

    private static func requiredField(_ name: String, from fields: [HTTPFieldLine]) throws -> String {
        guard let value = try optionalUniqueField(name, from: fields), !value.isEmpty else {
            throw QUICCodecError.malformed("required WebTransport field \(name) is missing")
        }
        return value
    }

    private static func optionalField(_ name: String, from fields: [HTTPFieldLine]) -> String? {
        fields.first { $0.name == name }?.value
    }

    private static func optionalUniqueField(_ name: String, from fields: [HTTPFieldLine]) throws -> String? {
        let matches = fields.filter { $0.name == name }
        guard matches.count <= 1 else {
            throw QUICCodecError.malformed("duplicate WebTransport field \(name)")
        }
        return matches.first?.value
    }
}

private struct StructuredFieldStringParser {
    private let scalars: [UnicodeScalar]
    private var index: Int

    init(_ value: String) {
        self.scalars = Array(value.unicodeScalars)
        self.index = 0
    }

    mutating func parseStringList() throws -> [String] {
        skipSpaces()
        guard !isAtEnd else { return [] }

        var items: [String] = []
        while true {
            items.append(try parseStringItem())
            skipSpaces()
            guard !isAtEnd else { return items }
            guard consume(",") else {
                throw QUICCodecError.malformed("Structured Field list expected comma")
            }
            skipSpaces()
            guard !isAtEnd else {
                throw QUICCodecError.malformed("Structured Field list has trailing comma")
            }
        }
    }

    mutating func parseStringItem() throws -> String {
        skipSpaces()
        let item = try parseBareString()
        skipParameters()
        skipSpaces()
        guard isAtEnd || current == "," else {
            throw QUICCodecError.malformed("Structured Field item has trailing bytes")
        }
        return item
    }

    private mutating func parseBareString() throws -> String {
        guard consume("\"") else {
            throw QUICCodecError.malformed("Structured Field item must be a string")
        }
        var output = String.UnicodeScalarView()
        while !isAtEnd {
            let scalar = scalars[index]
            index += 1
            if scalar == "\"" {
                return String(output)
            }
            if scalar == "\\" {
                guard !isAtEnd else {
                    throw QUICCodecError.malformed("Structured Field string has dangling escape")
                }
                let escaped = scalars[index]
                index += 1
                guard escaped == "\"" || escaped == "\\" else {
                    throw QUICCodecError.malformed("Structured Field string has invalid escape")
                }
                output.append(escaped)
                continue
            }
            guard scalar.value >= 0x20 && scalar.value <= 0x7e else {
                throw QUICCodecError.malformed("Structured Field string contains invalid character")
            }
            output.append(scalar)
        }
        throw QUICCodecError.malformed("Structured Field string is unterminated")
    }

    private mutating func skipParameters() {
        while true {
            skipSpaces()
            guard consume(";") else { return }
            while !isAtEnd, current != ",", current != ";" {
                index += 1
            }
        }
    }

    private mutating func skipSpaces() {
        while !isAtEnd, current == " " {
            index += 1
        }
    }

    private mutating func consume(_ scalar: UnicodeScalar) -> Bool {
        guard !isAtEnd, current == scalar else { return false }
        index += 1
        return true
    }

    private var current: UnicodeScalar {
        scalars[index]
    }

    private var isAtEnd: Bool {
        index >= scalars.count
    }
}

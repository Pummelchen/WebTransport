public enum WebTransportALPNPolicy {
    public static let requiredHTTP3Protocol = "h3"

    public static func validateNegotiatedProtocol(_ protocolName: String?) throws {
        guard protocolName == requiredHTTP3Protocol else {
            throw WebTransportDraft15Error(
                kind: .alpn,
                message: "WebTransport over HTTP/3 requires negotiated ALPN h3"
            )
        }
    }

    public static func validateOfferedProtocols(_ protocols: [String]) throws {
        guard protocols.contains(requiredHTTP3Protocol) else {
            throw WebTransportDraft15Error(
                kind: .alpn,
                message: "WebTransport over HTTP/3 requires ALPN offer h3"
            )
        }
    }
}

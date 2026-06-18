import Foundation
import Network

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum AppleQUICSpike {
    static func main() {
        printCapabilities()
    }

    static func printCapabilities() {
        let quic = makeQUIC()
        _ = quic

        print("Apple QUIC spike capabilities:")
        print("- QUIC protocol stack: Network.QUIC")
        print("- QUIC ALPN: configured with h3")
        print("- Listener type: NetworkListener<QUIC>")
        print("- Client connection type: NetworkConnection<QUIC>")
        print("- Bidirectional streams: NetworkConnection<QUIC>.openStream(.bidirectional)")
        print("- Unidirectional streams: NetworkConnection<QUIC>.openStream(.unidirectional)")
        print("- Inbound streams: NetworkConnection<QUIC>.inboundStreams")
        print("- Datagrams: NetworkConnection<QUIC>.datagrams")
        print("- Security prompts: none; this executable does not read or write keychains")
        print("- External dependencies: none")
    }

    static func makeQUIC() -> QUIC {
        QUIC(alpn: ["h3"]) {
            UDP()
        }
        .idleTimeout(30_000)
        .initialMaxData(1_048_576)
        .initialMaxStreamDataBidirectionalLocal(262_144)
        .initialMaxStreamDataBidirectionalRemote(262_144)
        .initialMaxStreamDataUnidirectional(262_144)
        .initialMaxBidirectionalStreams(16)
        .initialMaxUnidirectionalStreams(16)
        .maxDatagramFrameSize(1_200)
    }

    static func compileTimeAPIReferences(
        listener: NetworkListener<QUIC>,
        connection: NetworkConnection<QUIC>
    ) async throws {
        _ = listener.port
        _ = connection.negotiatedALPN
        _ = connection.remoteMaxStreamsBidirectional
        _ = connection.remoteMaxStreamsUnidirectional
        _ = connection.usableDatagramFrameSize
        _ = try await connection.openStream(directionality: .bidirectional)
        _ = try await connection.openStream(directionality: .unidirectional)
        _ = try await connection.datagrams
        try await connection.inboundStreams { stream in
            _ = stream.streamID
            _ = stream.directionality
            _ = stream.initiator
        }
    }
}

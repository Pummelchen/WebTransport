import Foundation
import Testing
import WebTransport
import WebTransportHTTP3Core
import WebTransportNetworkRuntime
import WebTransportQUICCore

/// F-swift-architecture-03: `WebTransportSession.datagramsAvailable` used to be
/// a hard-coded `true`. The QUIC transport parameter is not observable through
/// Network.framework before the datagram channel is first used, but H3 DATAGRAM
/// negotiation is: the peer's `SETTINGS_H3_DATAGRAM`. A profile that does not
/// advertise it must therefore report datagrams as unavailable, and the public
/// API must refuse a datagram instead of claiming the capability.
@Test
func sessionReportsDatagramsUnavailableWhenH3DatagramWasNotNegotiated() async throws {
    try await WebTransportProcessSupport.withExclusiveProcessExecution {
        try await runDatagramCapabilityExchange()
    }
}

private func runDatagramCapabilityExchange() async throws {
    var lastError: Error?
    for _ in 0..<5 {
        do {
            let server = WebTransportServer(
                configuration: WebTransportServerConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    supportedProtocols: ["demo.v1"],
                    // This profile advertises only SETTINGS_ENABLE_CONNECT_PROTOCOL;
                    // it never offers or requires SETTINGS_H3_DATAGRAM.
                    settingsValidation: .pywebtransportStreamInterop,
                    timeoutMilliseconds: 30_000
                )
            )
            let client = WebTransportClient(
                configuration: WebTransportClientConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    availableProtocols: ["demo.v1"],
                    trustPolicy: .localDevelopmentSelfSigned,
                    settingsValidation: .pywebtransportStreamInterop,
                    timeoutMilliseconds: 30_000
                )
            )
            let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
            defer { listener.shutdown() }

            async let accepted = listener.acceptSession()
            let session = try await client.connect(to: listener.localEndpoint)
            let serverSession = try await accepted
            defer {
                listener.shutdown()
            }

            #expect(session.selectedProtocol == "demo.v1")
            #expect(serverSession.selectedProtocol == "demo.v1")
            #expect(session.datagramsAvailable == false)
            #expect(serverSession.datagramsAvailable == false)

            // The refusal has to be the API's own, up front, not a framework
            // timeout after a datagram was already committed to the wire.
            await #expect(throws: WebTransportNetworkRuntimeError.self) {
                try await session.sendDatagram(Data("must-not-send".utf8))
            }

            try await session.close()
            try await Task.sleep(for: .seconds(2))
            return
        } catch {
            lastError = error
            try await Task.sleep(for: .seconds(2))
        }
    }
    throw lastError ?? QUICCodecError.malformed("datagram capability exchange failed")
}

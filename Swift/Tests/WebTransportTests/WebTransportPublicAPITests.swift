import Foundation
import Testing
import WebTransport
import WebTransportHTTP3Core
import WebTransportNetworkRuntime
import WebTransportQUICCore

@Test
func webTransportClientServerNetworkAPIConnectsAndEchoes() async throws {
    let (result, serverResult) = try await WebTransportProcessSupport.withExclusiveProcessExecution {
        try await runLoopbackPublicAPIExchange(
            protocols: ["demo.v1"],
            message: "ping"
        )
    }
    #expect(result.sessionEstablished)
    #expect(serverResult.sessionEstablished)
    #expect(result.message == "ping")
    #expect(serverResult.message == "ping")
    #expect(result.remoteEndpoint.port == serverResult.localEndpoint.port)
    #expect(serverResult.remoteEndpoint.port == result.localEndpoint.port)
}

@Test
func webTransportClientServerNetworkSessionExposesCloseLifecycle() async throws {
    try await WebTransportProcessSupport.withExclusiveProcessExecution {
        try await runLoopbackPublicAPISessionCloseExchange()
    }
}

@Test
func webTransportPublicAPILogsOnlySanitizedProductionEvents() async throws {
    let clientEvents = WebTransportEventRecorder()
    let serverEvents = WebTransportEventRecorder()
    let (result, _) = try await WebTransportProcessSupport.withExclusiveProcessExecution {
        try await runLoopbackPublicAPIExchange(
            protocols: ["demo.v1"],
            message: "secret-payload",
            clientLogger: WebTransportLogger { clientEvents.append($0) },
            serverLogger: WebTransportLogger { serverEvents.append($0) }
        )
    }
    #expect(result.message == "secret-payload")

    let descriptions = (clientEvents.snapshot() + serverEvents.snapshot()).map(\.description)
    #expect(descriptions.contains("webtransport.server_control_accepted"))
    #expect(descriptions.contains("webtransport.session_established role=client"))
    #expect(descriptions.contains("webtransport.session_established role=server"))
    for description in descriptions {
        #expect(!description.contains("secret-payload"))
        #expect(!description.contains("session="))
        #expect(!description.contains("session_id"))
    }
}

@Test
func webTransportEndpointParsesIPv4AndIPv6Forms() throws {
    #expect(try WebTransportEndpoint.parse("127.0.0.1:4433") == WebTransportEndpoint(host: "127.0.0.1", port: 4433))
    #expect(try WebTransportEndpoint.parse("[::1]:4433") == WebTransportEndpoint(host: "::1", port: 4433))
}

@Test
func webTransportPublicAPIRejectsUnsupportedTransportConfiguration() async throws {
    let client = WebTransportClient(configuration: WebTransportClientConfiguration(
        authority: "localhost",
        path: "/wt",
        transport: .frame
    ))
    await #expect(throws: WebTransportNetworkRuntimeError.self) {
        _ = try await client.connect(to: WebTransportEndpoint(host: "127.0.0.1", port: 4433))
    }
}

@Test
func webTransportPublicErrorSurfaceRedactsPeerControlledDetail() {
    let draftError = WebTransportDraft15Error(kind: .requirementsNotMet, message: "secret-origin https://internal.example")
    #expect(WebTransportErrorSurface.publicDescription(for: draftError) == "WebTransport peer requirements were not met")

    let codecError = QUICCodecError.malformed("secret packet bytes 010203")
    #expect(WebTransportErrorSurface.publicDescription(for: codecError) == "WebTransport protocol codec rejected malformed input")
}

private func makeLoopbackPublicAPIPair(
    protocols: [String],
    clientLogger: WebTransportLogger = .disabled,
    serverLogger: WebTransportLogger = .disabled
) async throws -> (WebTransportClient, WebTransportListeningServer) {
    let server = WebTransportServer(
        configuration: WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: protocols,
            timeoutMilliseconds: 30_000
        ),
        logger: serverLogger
    )
    let client = WebTransportClient(
        configuration: WebTransportClientConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            availableProtocols: protocols,
            trustPolicy: .localDevelopmentSelfSigned,
            timeoutMilliseconds: 30_000
        ),
        logger: clientLogger
    )
    let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
    return (client, listener)
}

private func runLoopbackPublicAPIExchange(
    protocols: [String],
    message: String,
    clientLogger: WebTransportLogger = .disabled,
    serverLogger: WebTransportLogger = .disabled
) async throws -> (WebTransportConnectionResult, WebTransportConnectionResult) {
    var lastError: Error?
    for _ in 0..<5 {
        do {
            let (client, listener) = try await makeLoopbackPublicAPIPair(
                protocols: protocols,
                clientLogger: clientLogger,
                serverLogger: serverLogger
            )
            defer {
                listener.shutdown()
            }
            async let served = listener.serveOne()
            let result = try await client.echo(to: listener.localEndpoint, message: message)
            let serverResult = try await served
            listener.shutdown()
            try await Task.sleep(for: .seconds(2))
            return (result, serverResult)
        } catch {
            lastError = error
            try await Task.sleep(for: .milliseconds(250))
        }
    }
    throw lastError ?? QUICCodecError.malformed("WebTransport public API exchange failed")
}

private func runLoopbackPublicAPISessionCloseExchange() async throws {
    var lastError: Error?
    for _ in 0..<8 {
        do {
            let (client, listener) = try await makeLoopbackPublicAPIPair(protocols: ["demo.v1"])
            defer {
                listener.shutdown()
            }
            async let accepted = listener.acceptSession()
            let session = try await client.connect(to: listener.localEndpoint)
            let serverSession = try await accepted

            #expect(session.selectedProtocol == "demo.v1")
            #expect(serverSession.selectedProtocol == "demo.v1")
            #expect(session.datagramsAvailable)
            #expect(serverSession.datagramsAvailable)
            #expect(session.remoteEndpoint.port == serverSession.localEndpoint.port)
            #expect(serverSession.remoteEndpoint.port == session.localEndpoint.port)

            try await session.drain()
            try await session.close(applicationErrorCode: 0, reason: "done")
            listener.shutdown()
            try await Task.sleep(for: .seconds(2))
            return
        } catch {
            lastError = error
            try await Task.sleep(for: .seconds(2))
        }
    }
    throw lastError ?? QUICCodecError.malformed("WebTransport public API session stream exchange failed")
}

private final class WebTransportEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [WebTransportLogEvent] = []

    func append(_ event: WebTransportLogEvent) {
        lock.lock()
        events.append(event)
        lock.unlock()
    }

    func snapshot() -> [WebTransportLogEvent] {
        lock.lock()
        let copy = events
        lock.unlock()
        return copy
    }
}

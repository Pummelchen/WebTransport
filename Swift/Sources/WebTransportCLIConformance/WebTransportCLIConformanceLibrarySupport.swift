import Foundation
import WebTransport
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple

// internal because the harness helpers and the scenario catalogue are in separate files
internal struct ManagerPair {
    var client: WebTransportSessionManager
    var server: WebTransportSessionManager
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func makeReadyPair(
    clientSettings: HTTP3Settings = .webTransportDraft16Defaults,
    serverSettings: HTTP3Settings = .webTransportDraft16Defaults,
    maxStreamReceiveBufferBytes: Int = 64 * 1024,
    maxDatagramFrameSize: Int = 1_200,
    maxDatagramReceiveBufferBytes: Int = 64 * 1024,
    maxBufferedStreamsPerSession: Int = 64,
    maxBufferedDatagramsPerSession: Int = 64,
    maxBufferedSessions: Int = 64
) throws -> ManagerPair {
    var clientHTTP3 = HTTP3ConnectionState(role: .client, localSettings: clientSettings)
    var serverHTTP3 = HTTP3ConnectionState(role: .server, localSettings: serverSettings)
    _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
    _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
    return ManagerPair(
        client: WebTransportSessionManager(
            http3: clientHTTP3,
            maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
            maxDatagramFrameSize: maxDatagramFrameSize,
            maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
            maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
            maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
            maxBufferedSessions: maxBufferedSessions
        ),
        server: WebTransportSessionManager(
            http3: serverHTTP3,
            maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
            maxDatagramFrameSize: maxDatagramFrameSize,
            maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
            maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
            maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
            maxBufferedSessions: maxBufferedSessions
        )
    )
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func establishDefaultSession(
    pair: inout ManagerPair,
    streamID: UInt64 = 0
) throws -> WebTransportSessionID {
    try establishSession(
        pair: &pair,
        streamID: streamID,
        request: WebTransportSessionRequest(authority: "example.com", path: streamID == 0 ? "/wt" : "/wt-\(streamID)"),
        policy: WebTransportServerSessionPolicy()
    )
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func establishSession(
    pair: inout ManagerPair,
    streamID: UInt64,
    request: WebTransportSessionRequest,
    policy: WebTransportServerSessionPolicy
) throws -> WebTransportSessionID {
    let requestFrame = try pair.client.makeClientSessionRequest(streamID: streamID, request: request)
    let decision = try pair.server.receiveClientSessionRequest(streamID: streamID, frame: requestFrame, policy: policy)
    let clientSession = try pair.client.receiveServerSessionResponse(streamID: streamID, frame: decision.responseFrame)
    try require(decision.session.state == .accepted, "server accepted session")
    try require(clientSession.state == .accepted, "client accepted session")
    return clientSession.id
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func rejectSession(
    pair: inout ManagerPair,
    streamID: UInt64,
    request: WebTransportSessionRequest,
    policy: WebTransportServerSessionPolicy
) throws -> WebTransportServerSessionDecision {
    let requestFrame = try pair.client.makeClientSessionRequest(streamID: streamID, request: request)
    let decision = try pair.server.receiveClientSessionRequest(streamID: streamID, frame: requestFrame, policy: policy)
    _ = try pair.client.receiveServerSessionResponse(streamID: streamID, frame: decision.responseFrame)
    return decision
}

// internal because the scenario runner in WebTransportCLIConformance.swift writes these logs
internal func writeFailureLog(result: WebTransportCLIConformanceResult, executableName: String, directory: URL) {
    let file = directory.appendingPathComponent("\(safe(executableName))-\(safe(result.name))-failure.log")
    let text = """
        timestamp=\(timestamp())
        executable=\(executableName)
        scenario=\(result.name)
        passed=false
        durationSeconds=\(format(result.durationSeconds))
        detail=\(result.detail)
        """
    try? text.write(to: file, atomically: true, encoding: .utf8)
}

// internal because the scenario runner in WebTransportCLIConformance.swift writes these logs
internal func writeSummaryLog(results: [WebTransportCLIConformanceResult], executableName: String, directory: URL) {
    let passed = count(.passed, in: results)
    let failed = count(.failed, in: results)
    let skipped = count(.skipped, in: results)
    let file = directory.appendingPathComponent("\(safe(executableName))-summary.log")
    let lines =
        [
            "timestamp=\(timestamp())",
            "executable=\(executableName)",
            "passed=\(passed)",
            "failed=\(failed)",
            "skipped=\(skipped)",
            "total=\(results.count)",
        ] + results.map { "\(statusToken($0.status)) \($0.name) \(format($0.durationSeconds))s \($0.detail)" }
    try? lines.joined(separator: "\n").write(to: file, atomically: true, encoding: .utf8)
}

private func safe(_ value: String) -> String {
    value.map { character in
        character.isLetter || character.isNumber || character == "-" ? character : "-"
    }.reduce(into: "") { $0.append($1) }
}

// internal because the scenario runner in WebTransportCLIConformance.swift prints through it
internal func format(_ value: Double) -> String {
    value.formatted(
        .number
            .grouping(.never)
            .precision(.fractionLength(4))
            .locale(Locale(identifier: "en_US_POSIX"))
    )
}

private func timestamp() -> String {
    ISO8601DateFormatter().string(from: Date())
}

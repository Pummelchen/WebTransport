// The session manager's actor isolation: it owns the HTTP/3 session manager and the
// parked waits on a session reaching `.closed`.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

actor WebTransportNetworkSessionManagerState {
    private var manager: WebTransportSessionManager

    /// A caller parked on a session reaching `.closed`.
    private struct ClosureWaiter {
        let id: UInt64
        let continuation: CheckedContinuation<Void, Never>
    }

    private var closureWaiters: [UInt64: [ClosureWaiter]] = [:]
    private var nextClosureWaiterID: UInt64 = 0

    /// How many times the session state was inspected on behalf of a closure
    /// wait. A cost probe for the regression test: parking a wait must not read
    /// the manager on a timer.
    private(set) var closureWaitStateReads = 0

    /// How many closure waits are parked right now.
    var waitingClosureCount: Int {
        closureWaiters.values.reduce(0) { $0 + $1.count }
    }

    init(manager: WebTransportSessionManager) {
        self.manager = manager
    }

    func withManager<T: Sendable>(_ body: @Sendable (inout WebTransportSessionManager) throws -> T) rethrows -> T {
        let result = try body(&manager)
        // Every mutation of the session state goes through here, so this is where
        // a parked wait learns that its session closed. Nothing polls the state on
        // a timer.
        resumeWaitersForClosedSessions()
        return result
    }

    /// Suspends until `sessionID` reaches `.closed` (or is gone), or the timeout
    /// expires.
    ///
    /// The close path resumes this from ``withManager(_:)``; the timeout is the
    /// only timer involved, and it is the caller's whole budget rather than a
    /// poll interval.
    func waitForSessionClosure(sessionID: UInt64, timeoutMilliseconds: Int32) async {
        if isSessionClosed(sessionID) {
            return
        }
        let waiterID = nextClosureWaiterID
        nextClosureWaiterID &+= 1
        let timeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(Int(max(0, timeoutMilliseconds))))
            await self?.expireClosureWaiter(sessionID: sessionID, id: waiterID)
        }
        defer { timeoutTask.cancel() }
        await withCheckedContinuation { continuation in
            // Re-check while still on the actor: cancellation or a close that
            // landed before registration must resume rather than park.
            guard !Task.isCancelled, !isSessionClosed(sessionID) else {
                continuation.resume()
                return
            }
            closureWaiters[sessionID, default: []].append(
                ClosureWaiter(id: waiterID, continuation: continuation)
            )
        }
    }

    private func isSessionClosed(_ sessionID: UInt64) -> Bool {
        closureWaitStateReads += 1
        guard let state = manager.sessionsByID[WebTransportSessionID(rawValue: sessionID)]?.state else {
            return true
        }
        if case .closed = state {
            return true
        }
        return false
    }

    private func resumeWaitersForClosedSessions() {
        guard !closureWaiters.isEmpty else {
            return
        }
        let closedSessionIDs = closureWaiters.keys.filter { isSessionClosed($0) }
        for sessionID in closedSessionIDs {
            guard let waiters = closureWaiters.removeValue(forKey: sessionID) else {
                continue
            }
            for waiter in waiters {
                waiter.continuation.resume()
            }
        }
    }

    private func expireClosureWaiter(sessionID: UInt64, id: UInt64) {
        removeClosureWaiter(sessionID: sessionID, id: id)?.continuation.resume()
    }

    private func removeClosureWaiter(sessionID: UInt64, id: UInt64) -> ClosureWaiter? {
        guard var waiters = closureWaiters[sessionID],
            let index = waiters.firstIndex(where: { $0.id == id })
        else {
            return nil
        }
        let waiter = waiters.remove(at: index)
        if waiters.isEmpty {
            closureWaiters.removeValue(forKey: sessionID)
        } else {
            closureWaiters[sessionID] = waiters
        }
        return waiter
    }
}

// The one-shot waits the helper layer parks on: a race whose loser is cancelled, a
// pending timer, and a gate that resumes exactly one waiter.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

/// Tracks a race between several ways of receiving the same thing.
///
/// Distinct from ``OneShotContinuation`` because a loss is not a result: only the
/// first success resumes the caller, and an error is surfaced solely when every
/// entrant has failed.
actor RaceCompletion {
    private var finished = false
    private var failures = 0
    private var firstError: Error?

    func succeed() -> Bool {
        guard !finished else {
            return false
        }
        finished = true
        return true
    }

    /// Returns the error to surface when this failure was the last one, and nil
    /// while another entrant could still win.
    func fail(_ error: Error, total: Int) -> Error? {
        guard !finished else {
            return nil
        }
        failures += 1
        if firstError == nil {
            firstError = error
        }
        guard failures >= total else {
            return nil
        }
        finished = true
        return firstError
    }
}

/// Owns a timeout task so it can be retired the moment its work completes.
///
/// The two events race: the operation can finish before the timer task has even
/// been handed over. Both paths funnel through one lock so the timer is
/// cancelled exactly once, whichever happens first, and never survives its
/// operation.
final class PendingTimer: @unchecked Sendable {
    private let state = Mutex<(task: Task<Void, Never>?, finished: Bool)>((nil, false))

    /// Hands the timer over. Cancels immediately if the work already finished.
    func arm(_ task: Task<Void, Never>) {
        let alreadyFinished = state.withLock { state -> Bool in
            state.task = task
            return state.finished
        }
        if alreadyFinished {
            task.cancel()
        }
    }

    /// Marks the work complete and cancels the timer if it has been armed.
    func operationFinished() {
        let task = state.withLock { state -> Task<Void, Never>? in
            state.finished = true
            return state.task
        }
        task?.cancel()
    }
}

actor OneShotContinuation {
    private var resumed = false

    func complete(_ operation: () -> Void) async {
        guard !resumed else {
            return
        }
        resumed = true
        operation()
    }
}

/// Parks one checked continuation and resumes it exactly once.
///
/// `withCheckedThrowingContinuation` does not observe task cancellation, so a
/// timeout has to resume the wait explicitly, while a state observer may resume
/// it at the same moment. This gate makes those two resumes mutually exclusive
/// and also survives the cancellation arriving before the wait has parked its
/// continuation: the later `park` sees the earlier resolution and resumes
/// immediately, so no caller is left suspended.
final class InteroperableQUICWaitGate: @unchecked Sendable {
    private enum Resolution {
        case pending
        case ready
        case failure(any Error)
    }

    private let state = Mutex<(resolution: Resolution, continuation: CheckedContinuation<Void, any Error>?)>(
        (.pending, nil)
    )

    func park(_ continuation: CheckedContinuation<Void, any Error>) {
        let resolution = state.withLock { state -> Resolution? in
            guard case .pending = state.resolution else {
                let resolution = state.resolution
                state.resolution = .pending
                return resolution
            }
            state.continuation = continuation
            return nil
        }
        if let resolution {
            Self.resume(continuation, with: resolution)
        }
    }

    func resolveReady() {
        resolve(.ready)
    }

    func resolveFailure(_ error: any Error) {
        resolve(.failure(error))
    }

    private func resolve(_ resolution: Resolution) {
        let continuation = state.withLock { state -> CheckedContinuation<Void, any Error>? in
            guard case .pending = state.resolution else {
                return nil
            }
            state.resolution = resolution
            let continuation = state.continuation
            state.continuation = nil
            return continuation
        }
        guard let continuation else {
            return
        }
        Self.resume(continuation, with: resolution)
    }

    private static func resume(
        _ continuation: CheckedContinuation<Void, any Error>,
        with resolution: Resolution
    ) {
        switch resolution {
        case .pending:
            break
        case .ready:
            continuation.resume()
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}

import Darwin
import Foundation
import Testing
import WebTransportLoopbackTestSupport

/// F-swift-perf-tests-10: the cross-process loopback lock must not be strandable
/// by a holder that dies, and both test targets must share one implementation.
@Suite("Loopback test lock")
struct WebTransportLoopbackTestLockTests {
    /// A path nothing else uses, so these tests never wait on the suite's own
    /// lock while it is held by a parallel loopback test.
    private func makeUniqueLockPath() -> String {
        (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("webtransport-loopback-lock-test-\(UUID().uuidString).lock")
    }

    @Test
    func aSecondHolderTimesOutAndTheOwnerIsNamed() async throws {
        let path = makeUniqueLockPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        // `-> Void` is load-bearing: without it the closure infers `#expect`'s result type,
        // `withLockAsync` becomes generic over a non-Void result, and the call is an unused
        // result under strict memory safety. An autofix removed it once and the test target
        // stopped compiling, so it is spelled out.
        try await WebTransportLoopbackTestLock.withLockAsync(label: "holder", filePath: path) { () async throws -> Void in
            await #expect(throws: WebTransportLoopbackTestLockTimeout.self) {
                try await WebTransportLoopbackTestLock.withLockAsync(
                    label: "second",
                    maximumWait: 0.2,
                    filePath: path
                ) {}
            }
        }

        // The holder released it, so the next taker gets it without waiting.
        let start = ContinuousClock.now
        try await WebTransportLoopbackTestLock.withLockAsync(label: "after", maximumWait: 5, filePath: path) {}
        #expect(ContinuousClock.now - start < .seconds(1))
    }

    /// The lock lives on the holder's open file description, not in the file.
    ///
    /// The old protocol acquired the lock by `mkdir`ing a directory and released
    /// it in a `defer`, so a holder that died left the directory behind and every
    /// waiter blocked for the full 180 s budget. Here the same artifact — a
    /// leftover file with a dead owner recorded in it — locks nothing, and the
    /// lock the kernel holds for the holder's descriptor is dropped when that
    /// descriptor goes away, which is exactly what process death does to it.
    @Test
    func theLockFollowsTheDescriptorAndNotALeftoverArtifact() async throws {
        let path = makeUniqueLockPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        try "dead-holder pid=999999".write(toFile: path, atomically: true, encoding: .utf8)
        let start = ContinuousClock.now
        try await WebTransportLoopbackTestLock.withLockAsync(
            label: "survivor",
            maximumWait: 5,
            filePath: path
        ) {}
        #expect(
            ContinuousClock.now - start < .seconds(1),
            "a leftover lock file stranded the lock, which is the mkdir failure mode"
        )

        // While a holder's descriptor is open, the lock is held.
        let descriptor = path.withCString { pointer in
            // SAFETY: the pointer is valid for this synchronous open call.
            unsafe Darwin.open(pointer, O_RDWR, 0)
        }
        try #require(descriptor >= 0)
        #expect(flock(descriptor, LOCK_EX | LOCK_NB) == 0)
        await #expect(throws: WebTransportLoopbackTestLockTimeout.self) {
            try await WebTransportLoopbackTestLock.withLockAsync(
                label: "waiter",
                maximumWait: 0.2,
                filePath: path
            ) {}
        }

        // The kernel drops the lock when the holder's descriptor closes, which is
        // what happens to every descriptor of a process that dies.
        close(descriptor)
        let afterDeath = ContinuousClock.now
        try await WebTransportLoopbackTestLock.withLockAsync(
            label: "after-death",
            maximumWait: 5,
            filePath: path
        ) {}
        #expect(ContinuousClock.now - afterDeath < .seconds(1))
    }
}

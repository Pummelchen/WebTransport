import Darwin
import Foundation

/// Serialises the loopback tests of every test target across processes.
///
/// The tests in `WebTransportTests` and `WebTransportNetworkRuntimeTests` bind
/// local ports and spawn CLI processes, so only one of them may run at a time.
/// Each target used to carry its own copy of that gate: an exclusive `mkdir` of a
/// hard-coded `/tmp` directory, held with a 180 s wait and released by a `defer`.
/// A process killed while holding it — a CI timeout, a `Ctrl-C`, a crash in a
/// test body — left the directory behind, and because nothing checked whether the
/// recorded owner was alive, every gated test in both targets then blocked for
/// 180 s and failed.
///
/// An exclusive `flock` on a lock file is released by the kernel when the holder
/// dies, so a dead owner cannot strand the lock, and the lock file is deliberately
/// never unlinked: two waiters that unlinked and re-created it could each lock a
/// different inode and both proceed.
public enum WebTransportLoopbackTestLock {
    /// How long a waiter blocks for a live holder before giving up.
    public static let defaultMaximumWait: TimeInterval = 180

    /// The lock file shared by every loopback test in the repository.
    public static var lockFilePath: String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent("webtransport-loopback-tests.lock")
    }

    /// Runs `body` while holding the loopback lock.
    public static func withLock<T>(
        label: String,
        maximumWait: TimeInterval = defaultMaximumWait,
        filePath: String = lockFilePath,
        _ body: () throws -> T
    ) throws -> T {
        let descriptor = try acquire(label: label, filePath: filePath, maximumWait: maximumWait)
        defer { release(descriptor) }
        return try body()
    }

    /// Runs `body` while holding the loopback lock.
    ///
    /// Distinct from the synchronous overload because overloads that differ only
    /// in the async-ness of their closure parameter are ambiguous at the call
    /// site in Swift 6.
    public static func withLockAsync<T>(
        label: String,
        maximumWait: TimeInterval = defaultMaximumWait,
        filePath: String = lockFilePath,
        _ body: () async throws -> T
    ) async throws -> T {
        let descriptor = try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    continuation.resume(
                        returning: try acquire(
                            label: label,
                            filePath: filePath,
                            maximumWait: maximumWait
                        )
                    )
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
        defer { release(descriptor) }
        return try await body()
    }

    private static func acquire(label: String, filePath: String, maximumWait: TimeInterval) throws -> Int32 {
        let descriptor = filePath.withCString { pointer in
            // SAFETY: the pointer is valid for this synchronous open call.
            unsafe Darwin.open(pointer, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        let deadline = Date().addingTimeInterval(maximumWait)
        while true {
            // SAFETY: `descriptor` is an open file descriptor owned by this scope.
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                writeOwner(label: label, to: descriptor)
                return descriptor
            }
            guard errno == EWOULDBLOCK else {
                let code = errno
                close(descriptor)
                throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
            }
            if Date() >= deadline {
                let owner = readOwner(filePath: filePath)
                close(descriptor)
                throw WebTransportLoopbackTestLockTimeout(owner: owner, waited: maximumWait)
            }
            usleep(10_000)
        }
    }

    private static func release(_ descriptor: Int32) {
        // Closing the descriptor drops the flock. The file is left in place on
        // purpose, so every waiter locks the same inode.
        // SAFETY: `descriptor` is the descriptor this lock acquired.
        _ = flock(descriptor, LOCK_UN)
        close(descriptor)
    }

    private static func writeOwner(label: String, to descriptor: Int32) {
        let owner = "\(label) pid=\(getpid())"
        let bytes = Array(owner.utf8)
        _ = ftruncate(descriptor, 0)
        _ = lseek(descriptor, 0, SEEK_SET)
        _ = bytes.withUnsafeBytes { buffer in
            // SAFETY: the buffer stays valid for the duration of the write.
            unsafe Darwin.write(descriptor, buffer.baseAddress, buffer.count)
        }
    }

    private static func readOwner(filePath: String) -> String {
        guard let data = FileManager.default.contents(atPath: filePath), !data.isEmpty else {
            return "unknown owner"
        }
        return String(decoding: data, as: UTF8.self)
    }
}

/// The lock is held by a live process for longer than the waiter's budget.
public struct WebTransportLoopbackTestLockTimeout: Error, CustomStringConvertible, Sendable {
    public let owner: String
    public let waited: TimeInterval

    public init(owner: String, waited: TimeInterval) {
        self.owner = owner
        self.waited = waited
    }

    public var description: String {
        "timed out after \(waited)s waiting for the loopback test lock held by \(owner)"
    }
}

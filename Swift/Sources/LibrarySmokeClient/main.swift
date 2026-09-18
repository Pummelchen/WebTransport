import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTestSupport
import WebTransportUDPApple

// internal because the runner type it formats timings for is in LibrarySmokeClientRunner.swift
internal func formatDuration(_ seconds: TimeInterval) -> String {
    seconds.formatted(
        .number
            .grouping(.never)
            .precision(.fractionLength(3))
            .locale(Locale(identifier: "en_US_POSIX"))
    )
}

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum LibrarySmokeClient {
    static func main() {
        do {
            let config = try parseArgs()
            var runner = try LibrarySmokeRunner(config: config)
            try runner.run()
            print("LibrarySmokeClient: smoke test passed")
        } catch {
            FileHandle.standardError.write(Data("LibrarySmokeClient failed: \(error)\n".utf8))
            exit(1)
        }
    }

    private static func parseArgs() throws -> LibrarySmokeRunner.Config {
        var config = LibrarySmokeRunner.Config()
        var index = 1
        let args = CommandLine.arguments
        while index < args.count {
            try apply(argument: args[index], args: args, index: &index, config: &config)
        }
        return config
    }

    /// One argument, one effect. The option and its value are consumed together, which is
    /// what the `index += 2` in every value-taking case used to spell out.
    private static func apply(
        argument: String,
        args: [String],
        index: inout Int,
        config: inout LibrarySmokeRunner.Config
    ) throws {
        switch argument {
        case "--host":
            config.host = try value(
                for: "--host",
                args: args,
                index: &index,
                missing: "missing value for --host"
            )
        case "--port":
            config.port = try checkedPort(value(for: "--port", args: args, index: &index))
        case "--iterations":
            config.iterations = try positiveInt(
                value(for: "--iterations", args: args, index: &index),
                option: "--iterations"
            )
        case "--max-datagram-frame-size":
            config.maxDatagramFrameSize = try positiveInt(
                value(for: "--max-datagram-frame-size", args: args, index: &index),
                option: "--max-datagram-frame-size"
            )
        case "--max-datagram-buffer":
            config.maxDatagramReceiveBufferBytes = try nonNegativeInt(
                value(for: "--max-datagram-buffer", args: args, index: &index),
                option: "--max-datagram-buffer"
            )
        case "--suite":
            config.runSuite = true
            index += 1
        case "--quick":
            config.runSuite = false
            index += 1
        case "--help":
            printUsage()
            exit(0)
        default:
            throw LibrarySmokeRunner.Error.syntax("unknown argument: \(argument)")
        }
    }

    /// The value that follows an option, advancing the index past both.
    private static func value(
        for option: String,
        args: [String],
        index: inout Int,
        missing: String? = nil
    ) throws -> String {
        guard index + 1 < args.count else {
            throw LibrarySmokeRunner.Error.syntax(missing ?? "missing or invalid value for \(option)")
        }
        let value = args[index + 1]
        index += 2
        return value
    }

    private static func checkedPort(_ raw: String) throws -> UInt16 {
        guard let value = UInt16(raw) else {
            throw LibrarySmokeRunner.Error.syntax("missing or invalid value for --port")
        }
        return value
    }

    private static func positiveInt(_ raw: String, option: String) throws -> Int {
        guard let value = Int(raw), value > 0 else {
            throw LibrarySmokeRunner.Error.syntax("missing or invalid value for \(option)")
        }
        return value
    }

    private static func nonNegativeInt(_ raw: String, option: String) throws -> Int {
        guard let value = Int(raw), value >= 0 else {
            throw LibrarySmokeRunner.Error.syntax("missing or invalid value for \(option)")
        }
        return value
    }

    private static func printUsage() {
        print("Usage: swift run LibrarySmokeClient --host <host> --port <port> [--suite|--quick]")
        print("  --host <host>   Server host (default 127.0.0.1)")
        print("  --port <port>   UDP port (default 45500)")
        print("  --iterations <n> Run repeated payload checks in loops (default 4)")
        print("  --suite          Run full protocol suite (default)")
        print("  --quick          Run single smoke path only")
    }
}

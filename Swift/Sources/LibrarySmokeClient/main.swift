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
            let arg = args[index]
            switch arg {
            case "--host":
                guard index + 1 < args.count else {
                    throw LibrarySmokeRunner.Error.syntax("missing value for --host")
                }
                config.host = args[index + 1]
                index += 2
            case "--port":
                guard index + 1 < args.count, let value = UInt16(args[index + 1]) else {
                    throw LibrarySmokeRunner.Error.syntax("missing or invalid value for --port")
                }
                config.port = value
                index += 2
            case "--iterations":
                guard index + 1 < args.count, let value = Int(args[index + 1]), value > 0 else {
                    throw LibrarySmokeRunner.Error.syntax("missing or invalid value for --iterations")
                }
                config.iterations = value
                index += 2
            case "--max-datagram-frame-size":
                guard index + 1 < args.count, let value = Int(args[index + 1]), value > 0 else {
                    throw LibrarySmokeRunner.Error.syntax("missing or invalid value for --max-datagram-frame-size")
                }
                config.maxDatagramFrameSize = value
                index += 2
            case "--max-datagram-buffer":
                guard index + 1 < args.count, let value = Int(args[index + 1]), value >= 0 else {
                    throw LibrarySmokeRunner.Error.syntax("missing or invalid value for --max-datagram-buffer")
                }
                config.maxDatagramReceiveBufferBytes = value
                index += 2
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
                throw LibrarySmokeRunner.Error.syntax("unknown argument: \(arg)")
            }
        }

        return config
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

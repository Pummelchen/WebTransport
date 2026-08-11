import Foundation
import WebTransportQUICCore

public enum WebTransportExporter {
    public static let tlsLabel = "EXPORTER-WebTransport"

    public static func context(
        sessionID: WebTransportSessionID,
        applicationLabel: Data,
        applicationContext: Data = Data()
    ) throws -> Data {
        guard applicationLabel.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("WebTransport exporter application label exceeds 255 bytes")
        }
        guard applicationContext.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("WebTransport exporter application context exceeds 255 bytes")
        }

        var output = Data()
        for shift in stride(from: 56, through: 0, by: -8) {
            output.append(UInt8((sessionID.rawValue >> UInt64(shift)) & 0xff))
        }
        output.append(UInt8(applicationLabel.count))
        output.append(applicationLabel)
        output.append(UInt8(applicationContext.count))
        output.append(applicationContext)
        return output
    }
}

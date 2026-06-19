import Foundation

public enum HTTP3FrameType {
    public static let data: UInt64 = 0x00
    public static let headers: UInt64 = 0x01
    public static let cancelPush: UInt64 = 0x03
    public static let settings: UInt64 = 0x04
    public static let pushPromise: UInt64 = 0x05
    public static let goaway: UInt64 = 0x07
    public static let maxPushID: UInt64 = 0x0d

    public static func isReserved(_ value: UInt64) -> Bool {
        value >= 0x21 && (value - 0x21).isMultiple(of: 0x1f)
    }
}

public enum HTTP3SettingID {
    public static let qpackMaxTableCapacity: UInt64 = 0x01
    public static let maxFieldSectionSize: UInt64 = 0x06
    public static let qpackBlockedStreams: UInt64 = 0x07
    public static let enableConnectProtocol: UInt64 = 0x08
    public static let h3Datagram: UInt64 = 0x33

    public static func isReservedHTTP2Setting(_ value: UInt64) -> Bool {
        value == 0x02 || value == 0x03 || value == 0x04 || value == 0x05
    }
}

public enum HTTP3StreamType {
    public static let control: UInt64 = 0x00
    public static let push: UInt64 = 0x01
    public static let qpackEncoder: UInt64 = 0x02
    public static let qpackDecoder: UInt64 = 0x03

    public static func isReserved(_ value: UInt64) -> Bool {
        value >= 0x21 && (value - 0x21).isMultiple(of: 0x1f)
    }
}

public struct WebTransportHTTP3DraftConstants: Equatable, Sendable {
    public var name: String
    public var revision: Int
    public var lastUpdated: String
    public var upgradeToken: String
    public var settingsEnableConnectProtocol: UInt64
    public var settingsH3Datagram: UInt64
    public var settingsWTEnabled: UInt64
    public var settingsWTInitialMaxStreamsUni: UInt64
    public var settingsWTInitialMaxStreamsBidi: UInt64
    public var settingsWTInitialMaxData: UInt64
    public var wtStreamFrame: UInt64
    public var webTransportStream: UInt64
    public var wtDrainSessionCapsule: UInt64
    public var wtCloseSessionCapsule: UInt64
    public var wtMaxDataCapsule: UInt64
    public var wtMaxStreamsBidiCapsule: UInt64
    public var wtMaxStreamsUniCapsule: UInt64
    public var wtDataBlockedCapsule: UInt64
    public var wtStreamsBlockedBidiCapsule: UInt64
    public var wtStreamsBlockedUniCapsule: UInt64
    public var wtBufferedStreamRejectedError: UInt64
    public var wtSessionGoneError: UInt64
    public var wtFlowControlError: UInt64
    public var wtALPNError: UInt64
    public var wtRequirementsNotMetError: UInt64
    public var wtApplicationErrorRange: ClosedRange<UInt64>

    public static let draft15 = WebTransportHTTP3DraftConstants(
        name: "draft-ietf-webtrans-http3-15",
        revision: 15,
        lastUpdated: "2026-03-02",
        upgradeToken: "webtransport-h3",
        settingsEnableConnectProtocol: HTTP3SettingID.enableConnectProtocol,
        settingsH3Datagram: HTTP3SettingID.h3Datagram,
        settingsWTEnabled: 0x2c7c_f000,
        settingsWTInitialMaxStreamsUni: 0x2b64,
        settingsWTInitialMaxStreamsBidi: 0x2b65,
        settingsWTInitialMaxData: 0x2b61,
        wtStreamFrame: 0x41,
        webTransportStream: 0x54,
        wtDrainSessionCapsule: 0x78ae,
        wtCloseSessionCapsule: 0x2843,
        wtMaxDataCapsule: 0x190b_4d3d,
        wtMaxStreamsBidiCapsule: 0x190b_4d3f,
        wtMaxStreamsUniCapsule: 0x190b_4d40,
        wtDataBlockedCapsule: 0x190b_4d41,
        wtStreamsBlockedBidiCapsule: 0x190b_4d43,
        wtStreamsBlockedUniCapsule: 0x190b_4d44,
        wtBufferedStreamRejectedError: 0x3994_bd84,
        wtSessionGoneError: 0x170d_7b68,
        wtFlowControlError: 0x045d_4487,
        wtALPNError: 0x0817_b3dd,
        wtRequirementsNotMetError: 0x212c_0d48,
        wtApplicationErrorRange: 0x52e4_a40f_a8db...0x52e5_ac98_3162
    )

    public static let current = draft15
}

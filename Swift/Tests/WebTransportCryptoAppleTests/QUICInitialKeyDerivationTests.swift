import Foundation
import Testing
import WebTransportCryptoApple

@Test
func derivesRFC9001InitialSecretVector() throws {
    let secrets = try QUICInitialKeyDerivation.deriveVersion1Secrets(
        destinationConnectionID: try Data(hex: "8394c8f03e515708")
    )

    let clientInitialSecret = try Data(hex: "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    let clientKey = try Data(hex: "1f369613dd76d5467730efcbe3b1a22d")
    let clientIV = try Data(hex: "fa044b2f42a3fd3b46fb255c")
    let clientHeaderProtectionKey = try Data(hex: "9f50449e04a0e810283a1e9933adedd2")
    let serverInitialSecret = try Data(hex: "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    let serverKey = try Data(hex: "cf3a5331653c364c88f0f379b6067e37")
    let serverIV = try Data(hex: "0ac1493ca1905853b0bba03e")
    let serverHeaderProtectionKey = try Data(hex: "c206b8d9b9f0f37644430b490eeaa314")

    #expect(secrets.clientInitialSecret == clientInitialSecret)
    #expect(secrets.clientKey == clientKey)
    #expect(secrets.clientIV == clientIV)
    #expect(secrets.clientHeaderProtectionKey == clientHeaderProtectionKey)
    #expect(secrets.serverInitialSecret == serverInitialSecret)
    #expect(secrets.serverKey == serverKey)
    #expect(secrets.serverIV == serverIV)
    #expect(secrets.serverHeaderProtectionKey == serverHeaderProtectionKey)
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw HexError.invalidLength
        }

        var output = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw HexError.invalidByte
            }
            output.append(byte)
            index = next
        }
        self = output
    }
}

private enum HexError: Error {
    case invalidLength
    case invalidByte
}

import Foundation

// The static table is data, and a large block of it. It lives in its own file so
// `QPACK.swift` stays under the file-length limit; nothing here depends on the codec.

public struct QPACKStaticTableEntry: Equatable, Sendable {
    public var index: UInt64
    public var name: String
    public var value: String
}

public enum QPACKStaticTable {
    public static let entries: [QPACKStaticTableEntry] = [
        QPACKStaticTableEntry(index: 0, name: ":authority", value: ""),
        QPACKStaticTableEntry(index: 1, name: ":path", value: "/"),
        QPACKStaticTableEntry(index: 2, name: "age", value: "0"),
        QPACKStaticTableEntry(index: 3, name: "content-disposition", value: ""),
        QPACKStaticTableEntry(index: 4, name: "content-length", value: "0"),
        QPACKStaticTableEntry(index: 5, name: "cookie", value: ""),
        QPACKStaticTableEntry(index: 6, name: "date", value: ""),
        QPACKStaticTableEntry(index: 7, name: "etag", value: ""),
        QPACKStaticTableEntry(index: 8, name: "if-modified-since", value: ""),
        QPACKStaticTableEntry(index: 9, name: "if-none-match", value: ""),
        QPACKStaticTableEntry(index: 10, name: "last-modified", value: ""),
        QPACKStaticTableEntry(index: 11, name: "link", value: ""),
        QPACKStaticTableEntry(index: 12, name: "location", value: ""),
        QPACKStaticTableEntry(index: 13, name: "referer", value: ""),
        QPACKStaticTableEntry(index: 14, name: "set-cookie", value: ""),
        QPACKStaticTableEntry(index: 15, name: ":method", value: "CONNECT"),
        QPACKStaticTableEntry(index: 16, name: ":method", value: "DELETE"),
        QPACKStaticTableEntry(index: 17, name: ":method", value: "GET"),
        QPACKStaticTableEntry(index: 18, name: ":method", value: "HEAD"),
        QPACKStaticTableEntry(index: 19, name: ":method", value: "OPTIONS"),
        QPACKStaticTableEntry(index: 20, name: ":method", value: "POST"),
        QPACKStaticTableEntry(index: 21, name: ":method", value: "PUT"),
        QPACKStaticTableEntry(index: 22, name: ":scheme", value: "http"),
        QPACKStaticTableEntry(index: 23, name: ":scheme", value: "https"),
        QPACKStaticTableEntry(index: 24, name: ":status", value: "103"),
        QPACKStaticTableEntry(index: 25, name: ":status", value: "200"),
        QPACKStaticTableEntry(index: 26, name: ":status", value: "304"),
        QPACKStaticTableEntry(index: 27, name: ":status", value: "404"),
        QPACKStaticTableEntry(index: 28, name: ":status", value: "503"),
        QPACKStaticTableEntry(index: 29, name: "accept", value: "*/*"),
        QPACKStaticTableEntry(index: 30, name: "accept", value: "application/dns-message"),
        QPACKStaticTableEntry(index: 31, name: "accept-encoding", value: "gzip, deflate, br"),
        QPACKStaticTableEntry(index: 32, name: "accept-ranges", value: "bytes"),
        QPACKStaticTableEntry(index: 33, name: "access-control-allow-headers", value: "cache-control"),
        QPACKStaticTableEntry(index: 34, name: "access-control-allow-headers", value: "content-type"),
        QPACKStaticTableEntry(index: 35, name: "access-control-allow-origin", value: "*"),
        QPACKStaticTableEntry(index: 36, name: "cache-control", value: "max-age=0"),
        QPACKStaticTableEntry(index: 37, name: "cache-control", value: "max-age=2592000"),
        QPACKStaticTableEntry(index: 38, name: "cache-control", value: "max-age=604800"),
        QPACKStaticTableEntry(index: 39, name: "cache-control", value: "no-cache"),
        QPACKStaticTableEntry(index: 40, name: "cache-control", value: "no-store"),
        QPACKStaticTableEntry(index: 41, name: "cache-control", value: "public, max-age=31536000"),
        QPACKStaticTableEntry(index: 42, name: "content-encoding", value: "br"),
        QPACKStaticTableEntry(index: 43, name: "content-encoding", value: "gzip"),
        QPACKStaticTableEntry(index: 44, name: "content-type", value: "application/dns-message"),
        QPACKStaticTableEntry(index: 45, name: "content-type", value: "application/javascript"),
        QPACKStaticTableEntry(index: 46, name: "content-type", value: "application/json"),
        QPACKStaticTableEntry(index: 47, name: "content-type", value: "application/x-www-form-urlencoded"),
        QPACKStaticTableEntry(index: 48, name: "content-type", value: "image/gif"),
        QPACKStaticTableEntry(index: 49, name: "content-type", value: "image/jpeg"),
        QPACKStaticTableEntry(index: 50, name: "content-type", value: "image/png"),
        QPACKStaticTableEntry(index: 51, name: "content-type", value: "text/css"),
        QPACKStaticTableEntry(index: 52, name: "content-type", value: "text/html; charset=utf-8"),
        QPACKStaticTableEntry(index: 53, name: "content-type", value: "text/plain"),
        QPACKStaticTableEntry(index: 54, name: "content-type", value: "text/plain;charset=utf-8"),
        QPACKStaticTableEntry(index: 55, name: "range", value: "bytes=0-"),
        QPACKStaticTableEntry(index: 56, name: "strict-transport-security", value: "max-age=31536000"),
        QPACKStaticTableEntry(index: 57, name: "strict-transport-security", value: "max-age=31536000; includesubdomains"),
        QPACKStaticTableEntry(index: 58, name: "strict-transport-security", value: "max-age=31536000; includesubdomains; preload"),
        QPACKStaticTableEntry(index: 59, name: "vary", value: "accept-encoding"),
        QPACKStaticTableEntry(index: 60, name: "vary", value: "origin"),
        QPACKStaticTableEntry(index: 61, name: "x-content-type-options", value: "nosniff"),
        QPACKStaticTableEntry(index: 62, name: "x-xss-protection", value: "1; mode=block"),
        QPACKStaticTableEntry(index: 63, name: ":status", value: "100"),
        QPACKStaticTableEntry(index: 64, name: ":status", value: "204"),
        QPACKStaticTableEntry(index: 65, name: ":status", value: "206"),
        QPACKStaticTableEntry(index: 66, name: ":status", value: "302"),
        QPACKStaticTableEntry(index: 67, name: ":status", value: "400"),
        QPACKStaticTableEntry(index: 68, name: ":status", value: "403"),
        QPACKStaticTableEntry(index: 69, name: ":status", value: "421"),
        QPACKStaticTableEntry(index: 70, name: ":status", value: "425"),
        QPACKStaticTableEntry(index: 71, name: ":status", value: "500"),
        QPACKStaticTableEntry(index: 72, name: "accept-language", value: ""),
        QPACKStaticTableEntry(index: 73, name: "access-control-allow-credentials", value: "FALSE"),
        QPACKStaticTableEntry(index: 74, name: "access-control-allow-credentials", value: "TRUE"),
        QPACKStaticTableEntry(index: 75, name: "access-control-allow-headers", value: "*"),
        QPACKStaticTableEntry(index: 76, name: "access-control-allow-methods", value: "get"),
        QPACKStaticTableEntry(index: 77, name: "access-control-allow-methods", value: "get, post, options"),
        QPACKStaticTableEntry(index: 78, name: "access-control-allow-methods", value: "options"),
        QPACKStaticTableEntry(index: 79, name: "access-control-expose-headers", value: "content-length"),
        QPACKStaticTableEntry(index: 80, name: "access-control-request-headers", value: "content-type"),
        QPACKStaticTableEntry(index: 81, name: "access-control-request-method", value: "get"),
        QPACKStaticTableEntry(index: 82, name: "access-control-request-method", value: "post"),
        QPACKStaticTableEntry(index: 83, name: "alt-svc", value: "clear"),
        QPACKStaticTableEntry(index: 84, name: "authorization", value: ""),
        QPACKStaticTableEntry(index: 85, name: "content-security-policy", value: "script-src 'none'; object-src 'none'; base-uri 'none'"),
        QPACKStaticTableEntry(index: 86, name: "early-data", value: "1"),
        QPACKStaticTableEntry(index: 87, name: "expect-ct", value: ""),
        QPACKStaticTableEntry(index: 88, name: "forwarded", value: ""),
        QPACKStaticTableEntry(index: 89, name: "if-range", value: ""),
        QPACKStaticTableEntry(index: 90, name: "origin", value: ""),
        QPACKStaticTableEntry(index: 91, name: "purpose", value: "prefetch"),
        QPACKStaticTableEntry(index: 92, name: "server", value: ""),
        QPACKStaticTableEntry(index: 93, name: "timing-allow-origin", value: "*"),
        QPACKStaticTableEntry(index: 94, name: "upgrade-insecure-requests", value: "1"),
        QPACKStaticTableEntry(index: 95, name: "user-agent", value: ""),
        QPACKStaticTableEntry(index: 96, name: "x-forwarded-for", value: ""),
        QPACKStaticTableEntry(index: 97, name: "x-frame-options", value: "deny"),
        QPACKStaticTableEntry(index: 98, name: "x-frame-options", value: "sameorigin"),
    ]

    public static func entry(index: UInt64) -> QPACKStaticTableEntry? {
        entries.first { $0.index == index }
    }

    public static func exactIndex(name: String, value: String) -> UInt64? {
        entries.first { $0.name == name && $0.value == value }?.index
    }

    public static func nameIndex(_ name: String) -> UInt64? {
        entries.first { $0.name == name }?.index
    }
}

// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKitCTarget

extension Data {
    public func isKey() -> Bool {
        return self.count == WG_KEY_LEN
    }

    public func hexKey() -> String? {
        if self.count != WG_KEY_LEN {
            return nil
        }
        var out = Data(repeating: 0, count: Int(WG_KEY_LEN_HEX))
        out.withUnsafeMutableInt8Bytes { outBytes in
            self.withUnsafeUInt8Bytes { inBytes in
                key_to_hex(outBytes, inBytes)
            }
        }
        out.removeLast()
        return String(data: out, encoding: .ascii)
    }

    public init?(hexKey hexString: String) {
        self.init(repeating: 0, count: Int(WG_KEY_LEN))

        if !self.withUnsafeMutableUInt8Bytes { key_from_hex($0, hexString) } {
            return nil
        }
    }

    public func base64Key() -> String? {
        if self.count != WG_KEY_LEN {
            return nil
        }
        var out = Data(repeating: 0, count: Int(WG_KEY_LEN_BASE64))
        out.withUnsafeMutableInt8Bytes { outBytes in
            self.withUnsafeUInt8Bytes { inBytes in
                key_to_base64(outBytes, inBytes)
            }
        }
        out.removeLast()
        return String(data: out, encoding: .ascii)
    }

    public init?(base64Key base64String: String) {
        self.init(repeating: 0, count: Int(WG_KEY_LEN))

        if !self.withUnsafeMutableUInt8Bytes { key_from_base64($0, base64String) } {
            return nil
        }
    }
}

extension Data {
    public func withUnsafeUInt8Bytes<R>(_ body: (UnsafePointer<UInt8>) -> R) -> R {
        assert(!isEmpty)
        return self.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> R in
            let bytes = ptr.bindMemory(to: UInt8.self)
            return body(bytes.baseAddress!) // might crash if self.count == 0
        }
    }

    public mutating func withUnsafeMutableUInt8Bytes<R>(_ body: (UnsafeMutablePointer<UInt8>) -> R) -> R {
        assert(!isEmpty)
        return self.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> R in
            let bytes = ptr.bindMemory(to: UInt8.self)
            return body(bytes.baseAddress!) // might crash if self.count == 0
        }
    }

    public mutating func withUnsafeMutableInt8Bytes<R>(_ body: (UnsafeMutablePointer<Int8>) -> R) -> R {
        assert(!isEmpty)
        return self.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> R in
            let bytes = ptr.bindMemory(to: Int8.self)
            return body(bytes.baseAddress!) // might crash if self.count == 0
        }
    }
}

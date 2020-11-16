// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKitCTarget

extension Data {
    init?(hexKey hexString: String) {
        var bytes = [UInt8](repeating: 0, count: Int(WG_KEY_LEN))
        if key_from_hex(&bytes, hexString) {
            self.init(bytes)
        } else {
            return nil
        }
    }

    init?(base64Key base64String: String) {
        var bytes = [UInt8](repeating: 0, count: Int(WG_KEY_LEN))
        if key_from_base64(&bytes, base64String) {
            self.init(bytes)
        } else {
            return nil
        }
    }

    func hexKey() -> String? {
        guard self.count == WG_KEY_LEN else {
            return nil
        }

        return withUnsafeBytes { rawBufferPointer -> String? in
            guard let inBytes = rawBufferPointer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            var outBytes = [CChar](repeating: 0, count: Int(WG_KEY_LEN_HEX))
            key_to_hex(&outBytes, inBytes)
            return String(cString: outBytes, encoding: .ascii)
        }
    }

    func base64Key() -> String? {
        guard self.count == WG_KEY_LEN else {
            return nil
        }

        return withUnsafeBytes { rawBufferPointer -> String? in
            guard let inBytes = rawBufferPointer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }
            var outBytes = [CChar](repeating: 0, count: Int(WG_KEY_LEN_BASE64))
            key_to_base64(&outBytes, inBytes)
            return String(cString: outBytes, encoding: .ascii)
        }
    }
}

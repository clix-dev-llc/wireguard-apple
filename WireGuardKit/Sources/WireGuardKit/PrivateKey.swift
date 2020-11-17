// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKitCTarget

/// A struct representing the private key used by WireGuard
public struct PrivateKey: StringKeyCoding, RawRepresentable, Equatable, Hashable {
    /// Raw private key representation
    public let rawValue: Data

    /// Derived public key
    public var publicKey: PublicKey {
        return rawValue.withUnsafeBytes { (privateKeyBufferPointer: UnsafeRawBufferPointer) -> PublicKey in
            var publicKeyData = Data(repeating: 0, count: Int(WG_KEY_LEN))
            let privateKeyBytes = privateKeyBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)

            publicKeyData.withUnsafeMutableBytes { (publicKeyBufferPointer: UnsafeMutableRawBufferPointer) in
                let publicKeyBytes = publicKeyBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                curve25519_derive_public_key(publicKeyBytes, privateKeyBytes)
            }

            return PublicKey(rawValue: publicKeyData)!
        }
    }

    /// Initialize new private key
    public init() {
        var privateKeyData = Data(repeating: 0, count: Int(WG_KEY_LEN))
        privateKeyData.withUnsafeMutableBytes { (rawBufferPointer: UnsafeMutableRawBufferPointer) in
            let privateKeyBytes = rawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            curve25519_generate_private_key(privateKeyBytes)
        }
        rawValue = privateKeyData
    }

    /// Initialize private key with existing raw representation
    public init?(rawValue: Data) {
        if rawValue.count == WG_KEY_LEN {
            self.rawValue = rawValue
        } else {
            return nil
        }
    }

    public static func == (lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        return compareKeys(lhs, rhs)
    }
}

/// A struct representing a public key used by WireGuard
public struct PublicKey: StringKeyCoding, RawRepresentable, Equatable, Hashable {
    /// Raw public key representation
    public let rawValue: Data

    /// Initialize public key with existing raw representation
    public init?(rawValue: Data) {
        if rawValue.count == WG_KEY_LEN {
            self.rawValue = rawValue
        } else {
            return nil
        }
    }

    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return compareKeys(lhs, rhs)
    }
}

/// A struct representing a pre-shared key used by WireGuard
public struct PreSharedKey: StringKeyCoding, RawRepresentable, Equatable, Hashable {
    /// Raw public key representation
    public let rawValue: Data

    /// Initialize pre-shared key with existing raw representation
    public init?(rawValue: Data) {
        if rawValue.count == WG_KEY_LEN {
            self.rawValue = rawValue
        } else {
            return nil
        }
    }

    public static func == (lhs: PreSharedKey, rhs: PreSharedKey) -> Bool {
        return compareKeys(lhs, rhs)
    }
}

/// Protocol describing the key representation
public protocol StringKeyCoding: RawRepresentable where RawValue == Data {
    /// Hex encoded representation
    var hexKey: String { get }

    /// Base64 encoded representation
    var base64Key: String { get }

    /// Initialize the key using hex representation
    init?(hexKey: String)

    /// Initialize the key using base64 representation
    init?(base64Key: String)
}

// Default implementations

extension StringKeyCoding {
    /// Hex encoded representation
    public var hexKey: String {
        return rawValue.withUnsafeBytes { (rawBufferPointer: UnsafeRawBufferPointer) -> String in
            let inBytes = rawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            var outBytes = [CChar](repeating: 0, count: Int(WG_KEY_LEN_HEX))
            key_to_hex(&outBytes, inBytes)
            return String(cString: outBytes, encoding: .ascii)!
        }
    }

    /// Base64 encoded representation
    public var base64Key: String {
        return rawValue.withUnsafeBytes { (rawBufferPointer: UnsafeRawBufferPointer) -> String in
            let inBytes = rawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            var outBytes = [CChar](repeating: 0, count: Int(WG_KEY_LEN_BASE64))
            key_to_base64(&outBytes, inBytes)
            return String(cString: outBytes, encoding: .ascii)!
        }
    }

    /// Initialize private key with hex representation
    public init?(hexKey: String) {
        var bytes = Data(repeating: 0, count: Int(WG_KEY_LEN))
        let success = bytes.withUnsafeMutableBytes { (bufferPointer: UnsafeMutableRawBufferPointer) -> Bool in
            return key_from_hex(bufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), hexKey)
        }
        if success {
            self.init(rawValue: bytes)
        } else {
            return nil
        }
    }

    /// Initialize private key with base64 representation
    public init?(base64Key: String) {
        var bytes = Data(repeating: 0, count: Int(WG_KEY_LEN))
        let success = bytes.withUnsafeMutableBytes { (bufferPointer: UnsafeMutableRawBufferPointer) -> Bool in
            return key_from_base64(bufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), base64Key)
        }
        if success {
            self.init(rawValue: bytes)
        } else {
            return nil
        }
    }
}

private func compareKeys<T>(_ lhs: T, _ rhs: T) -> Bool where T: RawRepresentable, T.RawValue == Data {
    return lhs.rawValue.withUnsafeBytes { (lhsBytes: UnsafeRawBufferPointer) -> Bool in
        return rhs.rawValue.withUnsafeBytes { (rhsBytes: UnsafeRawBufferPointer) -> Bool in
            return key_eq(
                lhsBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                rhsBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            )
        }
    }
}

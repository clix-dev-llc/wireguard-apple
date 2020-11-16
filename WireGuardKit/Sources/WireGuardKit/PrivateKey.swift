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
        var bytes = Data(repeating: 0, count: Int(WG_KEY_LEN))
        bytes.withUnsafeMutableBytes { (rawBufferPointer: UnsafeMutableRawBufferPointer) in
            let dataPointer = rawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            curve25519_generate_private_key(dataPointer)
        }
        rawValue = bytes
    }

    /// Initialize private key with existing raw representation
    public init?(rawValue: Data) {
        if rawValue.count == WG_KEY_LEN {
            self.rawValue = rawValue
        } else {
            return nil
        }
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
        return rawValue.hexKey()!
    }

    /// Base64 encoded representation
    public var base64Key: String {
        return rawValue.base64Key()!
    }

    /// Initialize private key with hex representation
    public init?(hexKey: String) {
        if let bytes = Data(hexKey: hexKey) {
            self.init(rawValue: bytes)
        } else {
            return nil
        }
    }

    /// Initialize private key with base64 representation
    public init?(base64Key: String) {
        if let bytes = Data(base64Key: base64Key) {
            self.init(rawValue: bytes)
        } else {
            return nil
        }
    }
}

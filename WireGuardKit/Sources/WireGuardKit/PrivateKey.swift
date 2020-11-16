// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKitCTarget

/// A struct representing the private key used by WireGuard
public struct PrivateKey: StringKeyCoding, RawRepresentable, Equatable {
    /// Raw private key representation
    public let rawValue: Data

    /// Derived public key
    public var publicKey: PublicKey {
        let publicKeyBytes = Curve25519.generatePublicKey(fromPrivateKey: rawValue)!
        return PublicKey(rawValue: publicKeyBytes)!
    }

    /// Initialize new private key
    public init() {
        rawValue = Curve25519.generatePrivateKey()
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
public struct PublicKey: StringKeyCoding, RawRepresentable, Equatable {
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
public struct PreSharedKey: StringKeyCoding, RawRepresentable, Equatable {
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

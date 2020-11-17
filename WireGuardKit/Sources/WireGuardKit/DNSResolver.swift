// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Network
import Foundation

enum DNSResolver {}

extension DNSResolver {

    static func isAllEndpointsAlreadyResolved(endpoints: [Endpoint?]) -> Bool {
        for endpoint in endpoints {
            guard let endpoint = endpoint else { continue }
            if !endpoint.hasHostAsIPAddress() {
                return false
            }
        }
        return true
    }

    static func resolveSync(endpoints: [Endpoint?]) -> [Endpoint?]? {
        let dispatchGroup = DispatchGroup()

        if isAllEndpointsAlreadyResolved(endpoints: endpoints) {
            return endpoints
        }

        var resolvedEndpoints: [Endpoint?] = Array(repeating: nil, count: endpoints.count)
        for (index, endpoint) in endpoints.enumerated() {
            guard let endpoint = endpoint else { continue }
            if endpoint.hasHostAsIPAddress() {
                resolvedEndpoints[index] = endpoint
            } else {
                let workItem = DispatchWorkItem {
                    resolvedEndpoints[index] = try? DNSResolver.resolveSync(endpoint: endpoint)
                }
                DispatchQueue.global(qos: .userInitiated).async(group: dispatchGroup, execute: workItem)
            }
        }

        dispatchGroup.wait() // TODO: Timeout?

        var hostnamesWithDnsResolutionFailure = [String]()
        assert(endpoints.count == resolvedEndpoints.count)
        for tuple in zip(endpoints, resolvedEndpoints) {
            let endpoint = tuple.0
            let resolvedEndpoint = tuple.1
            if let endpoint = endpoint {
                if resolvedEndpoint == nil {
                    guard let hostname = endpoint.hostname() else { fatalError() }
                    hostnamesWithDnsResolutionFailure.append(hostname)
                }
            }
        }
        if !hostnamesWithDnsResolutionFailure.isEmpty {
            // FIXME: somehow log that.
            // wg_log(.error, message: "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure.joined(separator: ", "))")
            return nil
        }
        return resolvedEndpoints
    }

    static func resolveSync(endpoint: Endpoint) throws -> Endpoint {
        guard case .name(let name, _) = endpoint.host else {
            return endpoint
        }

        var hints = addrinfo()
        hints.ai_flags = AI_ALL // We set this to ALL so that we get v4 addresses even on DNS64 networks
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP

        var resultPointer: UnsafeMutablePointer<addrinfo>?
        defer {
            resultPointer.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo(name, "\(endpoint.port)", &hints, &resultPointer)
        if errorCode != 0 {
            throw makeGetAddrInfoError(errorCode: errorCode)
        }

        var ipv4Address: IPv4Address?
        var ipv6Address: IPv6Address?

        var next: UnsafeMutablePointer<addrinfo>? = resultPointer
        let iterator = AnyIterator { () -> addrinfo? in
            let result = next?.pointee
            next = result?.ai_next
            return result
        }

        for addrInfo in iterator {
            if let maybeIpv4Address = IPv4Address(addrInfo: addrInfo) {
                ipv4Address = maybeIpv4Address
                break // If we found an IPv4 address, we can stop
            } else if let maybeIpv6Address = IPv6Address(addrInfo: addrInfo) {
                ipv6Address = maybeIpv6Address
                continue // If we already have an IPv6 address, we can skip this one
            }
        }

        // We prefer an IPv4 address over an IPv6 address
        if let ipv4Address = ipv4Address {
            return Endpoint(host: .ipv4(ipv4Address), port: endpoint.port)
        } else if let ipv6Address = ipv6Address {
            return Endpoint(host: .ipv6(ipv6Address), port: endpoint.port)
        } else {
            // Must never happen
            fatalError()
        }
    }
}

extension Endpoint {
    func withReresolvedIP() throws -> Endpoint {
        #if os(iOS)
        let hostname: String
        switch host {
        case .name(let name, _):
            hostname = name
        case .ipv4(let address):
            hostname = "\(address)"
        case .ipv6(let address):
            hostname = "\(address)"
        @unknown default:
            fatalError()
        }

        var hints = addrinfo()
        hints.ai_family = PF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        hints.ai_flags = AI_DEFAULT

        var result: UnsafeMutablePointer<addrinfo>?
        defer {
            result.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo("\(hostname)", "\(self.port)", &hints, &result)
        if errorCode != 0 {
            throw makeGetAddrInfoError(errorCode: errorCode)
        }

        let addrInfo = result!.pointee
        if let ipv4Address = IPv4Address(addrInfo: addrInfo) {
            return .ipv4(IPv4Endpoint(ip: ipv4Address, port: port))
        } else if let ipv6Address = IPv6Address(addrInfo: addrInfo) {
            return .ipv6(IPv6Endpoint(ip: ipv6Address, port: port))
        } else {
            fatalError()
        }
        #elseif os(macOS)
        return self
        #else
        #error("Unimplemented")
        #endif
    }
}

private func makeGetAddrInfoError(errorCode: Int32) -> NSError {
    let userInfo = [
        NSLocalizedDescriptionKey: String(cString: gai_strerror(errorCode))
    ]
    return NSError(domain: NSPOSIXErrorDomain, code: Int(errorCode), userInfo: userInfo)
}

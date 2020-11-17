// SPDX-License-Identifier: MIT
// Copyright © 2018-2019 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import NetworkExtension
import libwg_go

open class WireGuardPacketTunnelProvider: NEPacketTunnelProvider {

    /// An options dictionary key that's used for storing the activation identifier, supplied by the
    /// main bundle app, when starting the VPN tunnel programmatically.
    public static let activationAttemptIdentifierOptionsKey = "activationAttemptId"

    private let dispatchQueue = DispatchQueue(label: "PacketTunnel", qos: .utility)
    private var handle: Int32?
    private var networkMonitor: NWPathMonitor?
    private var packetTunnelSettingsGenerator: PacketTunnelSettingsGenerator?

    private(set) public var activationAttemptId: String?

    open override func startTunnel(options: [String: NSObject]?, completionHandler startTunnelCompletionHandler: @escaping (Error?) -> Void) {
        dispatchQueue.async {
            self.activationAttemptId = options?[Self.activationAttemptIdentifierOptionsKey] as? String

            // Configure WireGuard logger
            self.configureLogger()
            #if os(macOS)
            wgEnableRoaming(true)
            #endif

            self.logLine(level: .info, message: "Starting tunnel from the " + (self.activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

            self.loadTunnelConfigurationAndSetNetworkSettings { error in
                self.dispatchQueue.async {
                    if let error = error {
                        self.logLine(level: .error, message: "Starting tunnel failed: \(error.localizedDescription)")
                        self.handleTunnelError(error)
                        startTunnelCompletionHandler(error)
                    } else {
                        self.networkMonitor = NWPathMonitor()
                        self.networkMonitor!.pathUpdateHandler = { [weak self] path in
                            self?.pathUpdate(path: path)
                        }
                        self.networkMonitor!.start(queue: self.dispatchQueue)

                        let fileDescriptor = (self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32) ?? -1
                        if fileDescriptor < 0 {
                            self.logLine(level: .error, message: "Starting tunnel failed: Could not determine file descriptor")

                            let tunnelError = WireGuardPacketTunnelProviderError.tunnelDeviceFileDescriptor
                            self.handleTunnelError(tunnelError)
                            startTunnelCompletionHandler(tunnelError)
                            return
                        }

                        let ifname = Self.getInterfaceName(fileDescriptor: fileDescriptor)
                        self.logLine(level: .info, message: "Tunnel interface is \(ifname ?? "unknown")")

                        let handle = self.packetTunnelSettingsGenerator!.uapiConfiguration()
                            .withCString { return wgTurnOn($0, fileDescriptor) }
                        if handle < 0 {
                            self.logLine(level: .error, message: "Starting tunnel failed with wgTurnOn returning \(handle)")

                            let tunnelError = WireGuardPacketTunnelProviderError.startWireGuardBackend
                            self.handleTunnelError(tunnelError)
                            startTunnelCompletionHandler(tunnelError)
                            return
                        }
                        self.handle = handle

                        startTunnelCompletionHandler(nil)
                    }
                }
            }
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dispatchQueue.async {
            self.networkMonitor?.cancel()
            self.networkMonitor = nil

            self.logLine(level: .info, message: "Stopping tunnel")
            if let handle = self.handle {
                wgTurnOff(handle)
            }
            wgSetLogger(nil, nil)

            completionHandler()

            #if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
            #endif
        }
    }

    // MARK: - Subclassing

    open func handleTunnelError(_ error: WireGuardPacketTunnelProviderError) {
        // Implement in subclasses
    }

    open func logLine(level: PacketTunnelLogLevel, message: String) {
        // Implement in subclasses
    }

    open func getTunnelConfiguration(from tunnelProviderProtocol: NETunnelProviderProtocol) throws -> TunnelConfiguration {
        throw SubclassRequirementError()
    }

    // MARK: - Public

    public func getWireGuardConfiguration(completionHandler: @escaping (String?) -> Void) {
        dispatchQueue.async {
            guard let handle = self.handle else {
                completionHandler(nil)
                return
            }

            if let settings = wgGetConfig(handle) {
                completionHandler(String(cString: settings))
                free(settings)
            } else {
                completionHandler(nil)
            }
        }
    }

    public func reloadTunnelConfiguration(completionHandler: @escaping (WireGuardPacketTunnelProviderError?) -> Void) {
        self.dispatchQueue.async {
            self.logLine(level: .info, message: "Reloading tunnel configuration")

            // Tell the system that the tunnel is going to reconnect using new WireGuard
            // configuration.
            // This will broadcast the `NEVPNStatusDidChange` notification to the GUI process.
            self.reasserting = true

            self.loadTunnelConfigurationAndSetNetworkSettings { error in
                self.dispatchQueue.async {
                    if let error = error {
                        self.logLine(level: .error, message: "Reloading tunnel failed: \(error.localizedDescription)")
                        self.handleTunnelError(error)
                    } else {
                        if let handle = self.handle {
                            _ = self.packetTunnelSettingsGenerator?.uapiConfiguration()
                                .withCString { wgSetConfig(handle, $0) }
                        }
                    }

                    // Tell the system that the tunnel has finished reconnecting.
                    self.reasserting = false

                    completionHandler(error)
                }
            }
        }
    }

    // MARK: - Private


    /// Load tunnel configuration using available protocol configuration.
    /// - Throws: an error of type `WireGuardPacketTunnelProviderError`.
    /// - Returns: `TunnelConfiguration`.
    private func makeTunnelConfiguration() throws -> TunnelConfiguration {
        // Obtain protocol configuration
        guard let tunnelProviderProtocol = self.protocolConfiguration as? NETunnelProviderProtocol else {
            throw WireGuardPacketTunnelProviderError.missingProtocolConfiguration
        }

        do {
            return try self.getTunnelConfiguration(from: tunnelProviderProtocol)
        } catch {
            throw WireGuardPacketTunnelProviderError.loadTunnelConfiguration(error)
        }
    }

    private func loadTunnelConfigurationAndSetNetworkSettings(completionHandler: @escaping (WireGuardPacketTunnelProviderError?) -> Void) {
        // Read tunnel configuration
        let tunnelConfiguration: TunnelConfiguration
        do {
            tunnelConfiguration = try self.makeTunnelConfiguration()
        } catch let error as WireGuardPacketTunnelProviderError {
            completionHandler(error)
            return
        } catch {
            fatalError()
        }

        // Resolve peers
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        guard let resolvedEndpoints = DNSResolver.resolveSync(endpoints: endpoints) else {
            completionHandler(.dnsResolution)
            return
        }
        assert(endpoints.count == resolvedEndpoints.count)

        self.packetTunnelSettingsGenerator = PacketTunnelSettingsGenerator(tunnelConfiguration: tunnelConfiguration, resolvedEndpoints: resolvedEndpoints)

        let networkSettings = self.packetTunnelSettingsGenerator!.generateNetworkSettings()
        self.setTunnelNetworkSettings(networkSettings) { (error) in
            completionHandler(error.flatMap { .setNetworkSettings($0) })
        }
    }

    private class func getInterfaceName(fileDescriptor: Int32) -> String? {
        var ifnameBytes = [CChar](repeating: 0, count: Int(IF_NAMESIZE))

        return ifnameBytes.withUnsafeMutableBufferPointer { bufferPointer -> String? in
            guard let baseAddress = bufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(bufferPointer.count)
            let result = getsockopt(
                fileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress, &ifnameSize
            )

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    private func configureLogger() {
        let context = Unmanaged.passUnretained(self).toOpaque()

        wgSetLogger(context) { (context, logLevel, message) in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<WireGuardPacketTunnelProvider>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = PacketTunnelLogLevel(rawValue: logLevel) ?? .debug

            unretainedSelf.logLine(level: tunnelLogLevel, message: swiftString)
        }
    }

    private func pathUpdate(path: Network.NWPath) {
        guard let handle = handle else { return }

        self.logLine(level: .debug, message: "Network change detected with \(path.status) route and interface order \(path.availableInterfaces)")

        #if os(iOS)
        if let packetTunnelSettingsGenerator = packetTunnelSettingsGenerator {
            _ = packetTunnelSettingsGenerator.endpointUapiConfiguration()
                .withCString { return wgSetConfig(handle, $0) }
        }
        #endif
        wgBumpSockets(handle)
    }
}

/// An error type describing packet tunnel errors.
public enum WireGuardPacketTunnelProviderError: LocalizedError {
    /// Protocol configuration is not passed along with VPN configuration.
    case missingProtocolConfiguration

    /// Failure to parse tunnel configuration.
    case loadTunnelConfiguration(Error)

    /// A failure to resolve endpoints DNS.
    case dnsResolution

    /// A failure to set network settings.
    case setNetworkSettings(Error)

    /// A failure to obtain the tunnel device file descriptor.
    case tunnelDeviceFileDescriptor

    /// A failure to start WireGuard backend.
    case startWireGuardBackend

    public var errorDescription: String? {
        switch self {
        case .missingProtocolConfiguration:
            return "Missing protocol configuration"

        case .loadTunnelConfiguration(let error):
            return "Failure to load tunnel configuration: \(error.localizedDescription)"

        case .dnsResolution:
            return "Failure to resolve endpoints DNS"

        case .setNetworkSettings(let error):
            return "Failure to set network settings: \(error.localizedDescription)"

        case .tunnelDeviceFileDescriptor:
            return "Failure to obtain tunnel device file descriptor"

        case .startWireGuardBackend:
            return "Failure to start WireGuard backend"
        }
    }
}

/// An error type describing subclass requirement not being met
private struct SubclassRequirementError: LocalizedError {
    public var errorDescription: String? {
        return "Subclass does not implement the method"
    }
}

/// A enum describing packet tunnel log levels
public enum PacketTunnelLogLevel: Int32 {
    case debug = 0
    case info = 1
    case error = 2
}

enum WireGuardAdapterError: Error {
    /// Failure to locate socket descriptor.
    case cannotLocateSocketDescriptor

    /// Failure to perform an operation in such state
    case invalidState

    /// Failure to resolve endpoints
    case dnsResolution([(Endpoint, Error)])
}

protocol WireGuardAdapterDelegate: class {
    func wireguardAdapter(_ adapter: WireGuardAdapter, configureTunnelWithNetworkSettings networkSettings: NETunnelNetworkSettings)
}

class WireGuardAdapter {
    /// Adapter delegate
    private weak var delegate: WireGuardAdapterDelegate?

    /// Network routes monitor
    private var networkMonitor: NWPathMonitor?

    /// A tunnel device source socket file descriptor
    private let tunnelFileDescriptor: Int32

    /// A wireguard internal handle returned by `wgTurnOn` that's used to associate the calls
    /// with the specific WireGuard tunnel.
    private var wireguardHandle: Int32?

    /// A private queue used to synchronize access to `WireGuardAdapter` members
    private let workQueue = DispatchQueue(label: "WireGuardAdapterQueue")

    /// A logging function used for passing log entries
    private var logHandler: ((PacketTunnelLogLevel, String) -> Void)?

    /// Flag that tells if the adapter has already started
    private var isStarted = false

    // MARK: - Initialization

    /// A designated initializer
    class func fromPacketFlow(_ packetFlow: NEPacketTunnelFlow) throws -> WireGuardAdapter {
        if let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
            return WireGuardAdapter(tunnelFileDescriptor: fd)
        } else {
            throw WireGuardAdapterError.cannotLocateSocketDescriptor
        }
    }

    /// Private initializer
    private init(tunnelFileDescriptor: Int32) {
        self.tunnelFileDescriptor = tunnelFileDescriptor
    }

    deinit {
        // Force reset logger
        wgSetLogger(nil, nil)

        // Cancel network monitor
        networkMonitor?.cancel()
    }

    func setDelegate(_ delegate: WireGuardAdapterDelegate) {
        workQueue.async {
            self.delegate = delegate
        }
    }

    func setLogHandler(_ logHandler: @escaping (PacketTunnelLogLevel, String) -> Void) {
        workQueue.async {
            self.logHandler = logHandler
        }

        let context = Unmanaged.passUnretained(self).toOpaque()
        wgSetLogger(context) { (context, logLevel, message) in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = PacketTunnelLogLevel(rawValue: logLevel) ?? .debug

            unretainedSelf.handleLogLine(level: tunnelLogLevel, message: swiftString)
        }
    }

    func unsetLogHandler() {
        workQueue.async {
            self.logHandler = nil
        }
        wgSetLogger(nil, nil)
    }

    func start(configuration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard !self.isStarted else {
                completionHandler(.invalidState)
                return
            }

            #if os(macOS)
            wgEnableRoaming(true)
            #endif

            let networkMonitor = NWPathMonitor()
            networkMonitor.pathUpdateHandler = { [weak self] path in
                self?.didReceivePathUpdate(path: path)
            }

            networkMonitor.start(queue: self.workQueue)
            self.networkMonitor = networkMonitor

            // Resolve hostnames
            let endpoints = configuration.peers.map { $0.endpoint }
            var resolutionResults = [Result<Endpoint?, Error>]()

            for endpoint in endpoints {
                // Resolve hostnames
                if let endpoint = endpoint, case .name = endpoint.host {
                    do {
                        let resolvedEndpoint = try DNSResolver.resolveSync(endpoint: endpoint)
                        resolutionResults.append(.success(resolvedEndpoint))
                    } catch {
                        resolutionResults.append(.failure(error))
                    }
                } else {
                    resolutionResults.append(.success(endpoint))
                }
            }



            completionHandler(nil)
        }
    }

    func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard self.isStarted else {
                completionHandler(.invalidState)
                return
            }

            if let handle = self.wireguardHandle {
                wgTurnOff(handle)
                self.wireguardHandle = nil
            }

            completionHandler(nil)

            #if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
            #endif
        }
    }

    func setTunnelConfiguration(configuration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            // TODO: implement
        }
    }

    private func handleLogLine(level: PacketTunnelLogLevel, message: String) {
        workQueue.async {
            self.logHandler?(level, message)
        }
    }

    private func didReceivePathUpdate(path: Network.NWPath) {
        guard self.isStarted else { return }

        if let handle = self.wireguardHandle {
            wgBumpSockets(handle)
        }
    }
}

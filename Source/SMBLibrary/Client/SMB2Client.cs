/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using Utilities;
using ShareType = SMBLibrary.Services.ShareType;

namespace SMBLibrary.Client
{
    // ReSharper disable once InconsistentNaming
    public class SMB2Client : ISMBClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;
        public static readonly int ResponseTimeoutInMilliseconds = 5000;

        private string _serverName;
        private SMBTransportType _transport;
        private bool _isConnected;
        private bool _isLoggedIn;
        private Socket _clientSocket;

        private readonly object _incomingQueueLock = new();
        private readonly List<SMB2Command> _incomingQueue = new();
        private readonly EventWaitHandle _incomingQueueEventHandle = new(false, EventResetMode.AutoReset);

        private SessionPacket? _sessionResponsePacket;
        private readonly EventWaitHandle _sessionResponseEventHandle = new(false, EventResetMode.AutoReset);

        private uint _messageId;
        private SMB2Dialect _dialect;
        private bool _signingRequired;
        private byte[] _signingKey;
        private bool _encryptSessionData;
        private byte[] _encryptionKey;
        private byte[] _decryptionKey;
        private ulong _sessionId;
        private byte[] _securityBlob;
        private byte[] _sessionKey;
        private ushort _availableCredits = 1;

        public uint MaxTransactSize { get; private set; }

        public static void TrySendCommand(Socket socket, SMB2Command request, byte[]? encryptionKey)
        {
            var packet = new SessionMessagePacket();
            if (encryptionKey != null)
            {
                byte[] requestBytes = request.GetBytes();
                packet.Trailer = SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, request.Header.SessionID);
            }
            else
            {
                packet.Trailer = request.GetBytes();
            }

            TrySendPacket(socket, packet);
        }

        public static void TrySendPacket(Socket socket, SessionPacket packet)
        {
            try
            {
                byte[] packetBytes = packet.GetBytes();
                socket.Send(packetBytes);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        internal async Task<SMB2Command?> WaitForCommand(ulong messageId)
        {
            var stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < ResponseTimeoutInMilliseconds)
            {
                lock (_incomingQueueLock)
                {
                    for (int index = 0; index < _incomingQueue.Count; index++)
                    {
                        var command = _incomingQueue[index];

                        if (command.Header.MessageID == messageId)
                        {
                            _incomingQueue.RemoveAt(index);
                            if (command.Header.IsAsync && command.Header.Status == NTStatus.STATUS_PENDING)
                            {
                                index--;
                                continue;
                            }

                            return command;
                        }
                    }
                }

                await Task.Delay(100);
                _incomingQueueEventHandle.WaitOne(0);
            }

            return null;
        }

        internal void TrySendCommand(SMB2Command request, bool encryptData)
        {
            if (_dialect == SMB2Dialect.SMB202 || _transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                _availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (_availableCredits < request.Header.CreditCharge)
                {
                    throw new Exception("Not enough credits");
                }

                _availableCredits -= request.Header.CreditCharge;

                if (_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - _availableCredits);
                }
            }

            request.Header.MessageID = _messageId;
            request.Header.SessionID = _sessionId;
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (_signingRequired && !encryptData)
            {
                request.Header.IsSigned = _sessionId != 0 && (request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0 ||
                                                              _dialect == SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff);
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    byte[] buffer = request.GetBytes();
                    byte[] signature = SMB2Cryptography.CalculateSignature(_signingKey, _dialect, buffer, 0, buffer.Length);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }

            TrySendCommand(_clientSocket, request, encryptData ? _encryptionKey : null);
            if (_dialect == SMB2Dialect.SMB202 || _transport == SMBTransportType.NetBiosOverTCP)
            {
                _messageId++;
            }
            else
            {
                _messageId += request.Header.CreditCharge;
            }
        }

        public async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, int port)
        {
            if (string.IsNullOrEmpty(_serverName))
            {
                _serverName = serverAddress.ToString();
            }

            _transport = transport;
            if (_isConnected)
            {
                return _isConnected;
            }

            if (!ConnectSocket(serverAddress, port))
            {
                return false;
            }

            if (transport == SMBTransportType.NetBiosOverTCP)
            {
                SessionRequestPacket sessionRequest = new()
                {
                    CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService),
                    CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService)
                };
                TrySendPacket(_clientSocket, sessionRequest);

                SessionPacket sessionResponsePacket = WaitForSessionResponsePacket();
                if (sessionResponsePacket is not PositiveSessionResponsePacket)
                {
                    _clientSocket.Disconnect(false);
                    if (!ConnectSocket(serverAddress, port))
                    {
                        return false;
                    }

                    NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
                    string serverName = nameServiceClient.GetServerName();
                    if (string.IsNullOrEmpty(serverName))
                    {
                        return false;
                    }

                    sessionRequest.CalledName = serverName;
                    TrySendPacket(_clientSocket, sessionRequest);

                    sessionResponsePacket = WaitForSessionResponsePacket();
                    if (sessionResponsePacket is not PositiveSessionResponsePacket)
                    {
                        return false;
                    }
                }
            }

            bool supportsDialect = await NegotiateDialect();
            if (!supportsDialect)
            {
                _clientSocket.Close();
            }
            else
            {
                _isConnected = true;
            }

            return _isConnected;
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public Task<bool> Connect(string serverName, SMBTransportType transport)
        {
            _serverName = serverName;
            IPHostEntry hostEntry = Dns.GetHostEntry(serverName);
            if (hostEntry.AddressList.Length == 0)
            {
                throw new Exception($"Cannot resolve host name {serverName} to an IP address");
            }

            IPAddress serverAddress = hostEntry.AddressList[0];
            return Connect(serverAddress, transport);
        }

        public Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            int port = transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort;
            return Connect(serverAddress, transport, port);
        }

        public void Disconnect()
        {
            if (_isConnected)
            {
                _clientSocket.Disconnect(false);
                _isConnected = false;
            }
        }

        public Task<NTStatus> Login(string domainName, string userName, string password)
        {
            return Login(domainName, userName, password, AuthenticationMethod.NTLMv2);
        }

        public async Task<NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            byte[] negotiateMessage = NTLMAuthenticationHelper.GetNegotiateMessage(_securityBlob, domainName, authenticationMethod);
            if (negotiateMessage == null)
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            SessionSetupRequest request = new SessionSetupRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                SecurityBuffer = negotiateMessage
            };
            TrySendCommand(request);
            var response = await WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED && response is SessionSetupResponse)
                {
                    byte[] authenticateMessage = NTLMAuthenticationHelper.GetAuthenticateMessage(((SessionSetupResponse)response).SecurityBuffer, domainName, userName, password, authenticationMethod, out _sessionKey);
                    if (authenticateMessage == null)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }

                    _sessionId = response.Header.SessionID;
                    request = new SessionSetupRequest
                    {
                        SecurityMode = SecurityMode.SigningEnabled,
                        SecurityBuffer = authenticateMessage
                    };
                    TrySendCommand(request);
                    response = await WaitForCommand(request.MessageID);
                    if (response != null)
                    {
                        _isLoggedIn = response.Header.Status == NTStatus.STATUS_SUCCESS;
                        if (_isLoggedIn)
                        {
                            _signingKey = SMB2Cryptography.GenerateSigningKey(_sessionKey, _dialect, null);
                            if (_dialect == SMB2Dialect.SMB300)
                            {
                                _encryptSessionData = (((SessionSetupResponse)response).SessionFlags & SessionFlags.EncryptData) > 0;
                                _encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(_sessionKey, SMB2Dialect.SMB300, null);
                                _decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(_sessionKey, SMB2Dialect.SMB300, null);
                            }
                        }

                        return response.Header.Status;
                    }
                }
                else
                {
                    return response.Header.Status;
                }
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<NTStatus> Logoff()
        {
            if (!_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();
            TrySendCommand(request);

            var response = await WaitForCommand(request.MessageID);
            if (response != null)
            {
                _isLoggedIn = response.Header.Status != NTStatus.STATUS_SUCCESS;
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<StatusResult<List<string>?>> ListShares()
        {
            if (!_isConnected || !_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var treeConnectResult = await TreeConnect("IPC$");
            var namedPipeShare = treeConnectResult.Result;
            if (namedPipeShare == null)
            {
                return new StatusResult<List<string>?>(null, treeConnectResult.Status);
            }

            var listSharesResult = await ServerServiceHelper.ListShares(namedPipeShare, _serverName, ShareType.DiskDrive);
            var shares = listSharesResult.Result;
            var status = listSharesResult.Status;

            await namedPipeShare.Disconnect();
            return new StatusResult<List<string>?>(shares, status);
        }

        public async Task<StatusResult<ISMBFileStore?>> TreeConnect(string shareName)
        {
            if (!_isConnected || !_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            NTStatus status;
            string sharePath = $@"\\{_serverName}\{shareName}";
            var request = new TreeConnectRequest
            {
                Path = sharePath
            };
            TrySendCommand(request);
            var response = await WaitForCommand(request.MessageID);
            if (response != null)
            {
                status = response.Header.Status;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse)
                {
                    bool encryptShareData = (((TreeConnectResponse)response).ShareFlags & ShareFlags.EncryptData) > 0;
                    var store = new SMB2FileStore(this, response.Header.TreeID, _encryptSessionData || encryptShareData);
                    return new StatusResult<ISMBFileStore?>(store, status);
                }
            }
            else
            {
                status = NTStatus.STATUS_INVALID_SMB;
            }

            return new StatusResult<ISMBFileStore?>(null, status);
        }

        public uint MaxReadSize { get; private set; }

        public uint MaxWriteSize { get; private set; }

        private SessionPacket WaitForSessionResponsePacket()
        {
            const int timeOut = 5000;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < timeOut)
            {
                if (_sessionResponsePacket != null)
                {
                    SessionPacket result = _sessionResponsePacket;
                    _sessionResponsePacket = null;
                    return result;
                }

                _sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void TrySendCommand(SMB2Command request)
        {
            TrySendCommand(request, _encryptSessionData);
        }

        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                _clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            ConnectionState state = new ConnectionState(_clientSocket);
            NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
            _clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, OnClientSocketReceive, state);
            return true;
        }

        private async Task<bool> NegotiateDialect()
        {
            NegotiateRequest request = new NegotiateRequest
            {
                SecurityMode = SecurityMode.SigningEnabled,
                Capabilities = Capabilities.Encryption,
                ClientGuid = Guid.NewGuid(),
                ClientStartTime = DateTime.Now
            };
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);

            TrySendCommand(request);
            var response = await WaitForCommand(request.MessageID) as NegotiateResponse;
            if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS)
            {
                _dialect = response.DialectRevision;
                _signingRequired = (response.SecurityMode & SecurityMode.SigningRequired) > 0;
                MaxTransactSize = Math.Min(response.MaxTransactSize, ClientMaxTransactSize);
                MaxReadSize = Math.Min(response.MaxReadSize, ClientMaxReadSize);
                MaxWriteSize = Math.Min(response.MaxWriteSize, ClientMaxWriteSize);
                _securityBlob = response.SecurityBuffer;
                return true;
            }

            return false;
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!clientSocket.Connected)
            {
                return;
            }

            int numberOfBytesReceived = 0;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                return;
            }
            catch (SocketException ex)
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                _isConnected = false;
            }
            else
            {
                NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                ProcessConnectionBuffer(state);

                try
                {
                    clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, OnClientSocketReceive, state);
                }
                catch (ObjectDisposedException)
                {
                    _isConnected = false;
                    Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                }
                catch (SocketException ex)
                {
                    _isConnected = false;
                    Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket? packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    state.ClientSocket.Close();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                if (_dialect == SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0))
                {
                    SMB2TransformHeader transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                    byte[] encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
                    messageBytes = SMB2Cryptography.DecryptMessage(_decryptionKey, transformHeader, encryptedMessage);
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    _isConnected = false;
                    return;
                }

                _availableCredits += command.Header.Credits;

                if (_transport == SMBTransportType.DirectTCPTransport && command is NegotiateResponse)
                {
                    NegotiateResponse negotiateResponse = (NegotiateResponse)command;
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client MUST disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value, we add 256 bytes.
                        int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize) + 256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                        {
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                {
                    lock (_incomingQueueLock)
                    {
                        _incomingQueue.Add(command);
                        _incomingQueueEventHandle.Set();
                    }
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && _transport == SMBTransportType.NetBiosOverTCP)
            {
                _sessionResponsePacket = packet;
                _sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && _transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
            }
        }

        private static void Log(string message)
        {
            Debug.Print(message);
        }
    }
}
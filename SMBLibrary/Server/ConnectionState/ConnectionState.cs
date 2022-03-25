/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.NetBios;
using Utilities;

namespace SMBLibrary.Server
{
    internal delegate void LogDelegate(Severity severity, string message);

    internal class ConnectionState
    {
        private readonly Reference<DateTime> m_lastSendDTRef; // We must use a reference because the sender thread will keep using the original ConnectionState object
        private readonly LogDelegate LogToServerHandler;
        public SMBDialect Dialect;
        public GSSContext AuthenticationContext;

        public ConnectionState(Socket clientSocket, IPEndPoint clientEndPoint, LogDelegate logToServerHandler)
        {
            ClientSocket = clientSocket;
            ClientEndPoint = clientEndPoint;
            ReceiveBuffer = new NBTConnectionReceiveBuffer();
            SendQueue = new BlockingQueue<SessionPacket>();
            CreationDT = DateTime.UtcNow;
            LastReceiveDT = DateTime.UtcNow;
            m_lastSendDTRef = DateTime.UtcNow;
            LogToServerHandler = logToServerHandler;
            Dialect = SMBDialect.NotSet;
        }

        public ConnectionState(ConnectionState state)
        {
            ClientSocket = state.ClientSocket;
            ClientEndPoint = state.ClientEndPoint;
            ReceiveBuffer = state.ReceiveBuffer;
            SendQueue = state.SendQueue;
            CreationDT = state.CreationDT;
            LastReceiveDT = state.LastReceiveDT;
            m_lastSendDTRef = state.LastSendDTRef;
            LogToServerHandler = state.LogToServerHandler;
            Dialect = state.Dialect;
        }

        public Socket ClientSocket { get; }

        public IPEndPoint ClientEndPoint { get; }

        public NBTConnectionReceiveBuffer ReceiveBuffer { get; }

        public BlockingQueue<SessionPacket> SendQueue { get; }

        public DateTime CreationDT { get; }

        public DateTime LastReceiveDT { get; private set; }

        public DateTime LastSendDT => LastSendDTRef.Value;

        internal Reference<DateTime> LastSendDTRef => m_lastSendDTRef;

        public string ConnectionIdentifier
        {
            get
            {
                if (ClientEndPoint != null)
                {
                    return ClientEndPoint.Address + ":" + ClientEndPoint.Port;
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Free all resources used by the active sessions in this connection
        /// </summary>
        public virtual void CloseSessions()
        {
        }

        public virtual List<SessionInformation> GetSessionsInformation()
        {
            return new List<SessionInformation>();
        }

        public void LogToServer(Severity severity, string message)
        {
            message = string.Format("[{0}] {1}", ConnectionIdentifier, message);
            if (LogToServerHandler != null)
            {
                LogToServerHandler(severity, message);
            }
        }

        public void LogToServer(Severity severity, string message, params object[] args)
        {
            LogToServer(severity, string.Format(message, args));
        }

        public void UpdateLastReceiveDT()
        {
            LastReceiveDT = DateTime.UtcNow;
        }

        public void UpdateLastSendDT()
        {
            m_lastSendDTRef.Value = DateTime.UtcNow;
        }
    }
}
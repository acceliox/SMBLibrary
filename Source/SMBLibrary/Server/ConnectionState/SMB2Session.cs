/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using SMBLibrary.SMB2;

namespace SMBLibrary.Server
{
    internal class SMB2Session
    {
        private SMB2ConnectionState m_connection;
        private ulong m_sessionID;
        private readonly SecurityContext m_securityContext;

        // Key is TreeID
        private readonly Dictionary<uint, ISMBShare> m_connectedTrees = new Dictionary<uint, ISMBShare>();
        private uint m_nextTreeID = 1; // TreeID uniquely identifies a tree connect within the scope of the session

        // Key is the volatile portion of the FileID
        private readonly Dictionary<ulong, OpenFileObject> m_openFiles = new Dictionary<ulong, OpenFileObject>();
        private ulong m_nextVolatileFileID = 1;

        // Key is the volatile portion of the FileID
        private readonly Dictionary<ulong, OpenSearch> m_openSearches = new Dictionary<ulong, OpenSearch>();

        public SMB2Session(SMB2ConnectionState connection, ulong sessionID, string userName, string machineName, byte[] sessionKey, object accessToken, bool signingRequired, byte[] signingKey)
        {
            m_connection = connection;
            m_sessionID = sessionID;
            SessionKey = sessionKey;
            m_securityContext = new SecurityContext(userName, machineName, connection.ClientEndPoint, connection.AuthenticationContext, accessToken);
            CreationDT = DateTime.UtcNow;
            SigningRequired = signingRequired;
            SigningKey = signingKey;
        }

        public byte[] SessionKey { get; }

        public SecurityContext SecurityContext => m_securityContext;

        public string UserName => m_securityContext.UserName;

        public string MachineName => m_securityContext.MachineName;

        public DateTime CreationDT { get; }

        public bool SigningRequired { get; }

        public byte[] SigningKey { get; }

        public uint? AddConnectedTree(ISMBShare share)
        {
            lock (m_connectedTrees)
            {
                uint? treeID = AllocateTreeID();
                if (treeID.HasValue)
                {
                    m_connectedTrees.Add(treeID.Value, share);
                }

                return treeID;
            }
        }

        public ISMBShare GetConnectedTree(uint treeID)
        {
            ISMBShare result;
            m_connectedTrees.TryGetValue(treeID, out result);
            return result;
        }

        public void DisconnectTree(uint treeID)
        {
            ISMBShare share;
            m_connectedTrees.TryGetValue(treeID, out share);
            if (share != null)
            {
                lock (m_openFiles)
                {
                    List<ulong> fileIDList = new List<ulong>(m_openFiles.Keys);
                    foreach (ulong fileID in fileIDList)
                    {
                        OpenFileObject openFile = m_openFiles[fileID];
                        if (openFile.TreeID == treeID)
                        {
                            share.FileStore.CloseFile(openFile.Handle);
                            m_openFiles.Remove(fileID);
                        }
                    }
                }

                lock (m_connectedTrees)
                {
                    m_connectedTrees.Remove(treeID);
                }
            }
        }

        public bool IsTreeConnected(uint treeID)
        {
            return m_connectedTrees.ContainsKey(treeID);
        }

        public FileID? AddOpenFile(uint treeID, string shareName, string relativePath, object handle, FileAccess fileAccess)
        {
            lock (m_openFiles)
            {
                ulong? volatileFileID = AllocateVolatileFileID();
                if (volatileFileID.HasValue)
                {
                    FileID fileID = new FileID();
                    fileID.Volatile = volatileFileID.Value;
                    // [MS-SMB2] FileId.Persistent MUST be set to Open.DurableFileId.
                    // Note: We don't support durable handles so we use volatileFileID.
                    fileID.Persistent = volatileFileID.Value;
                    m_openFiles.Add(volatileFileID.Value, new OpenFileObject(treeID, shareName, relativePath, handle, fileAccess));
                    return fileID;
                }
            }

            return null;
        }

        public OpenFileObject GetOpenFileObject(FileID fileID)
        {
            OpenFileObject result;
            m_openFiles.TryGetValue(fileID.Volatile, out result);
            return result;
        }

        public void RemoveOpenFile(FileID fileID)
        {
            lock (m_openFiles)
            {
                m_openFiles.Remove(fileID.Volatile);
            }

            m_openSearches.Remove(fileID.Volatile);
        }

        public List<OpenFileInformation> GetOpenFilesInformation()
        {
            List<OpenFileInformation> result = new List<OpenFileInformation>();
            lock (m_openFiles)
            {
                foreach (OpenFileObject openFile in m_openFiles.Values)
                {
                    result.Add(new OpenFileInformation(openFile.ShareName, openFile.Path, openFile.FileAccess, openFile.OpenedDT));
                }
            }

            return result;
        }

        public OpenSearch AddOpenSearch(FileID fileID, List<QueryDirectoryFileInformation> entries, int enumerationLocation)
        {
            OpenSearch openSearch = new OpenSearch(entries, enumerationLocation);
            m_openSearches.Add(fileID.Volatile, openSearch);
            return openSearch;
        }

        public OpenSearch GetOpenSearch(FileID fileID)
        {
            OpenSearch openSearch;
            m_openSearches.TryGetValue(fileID.Volatile, out openSearch);
            return openSearch;
        }

        public void RemoveOpenSearch(FileID fileID)
        {
            m_openSearches.Remove(fileID.Volatile);
        }

        /// <summary>
        /// Free all resources used by this session
        /// </summary>
        public void Close()
        {
            List<uint> treeIDList = new List<uint>(m_connectedTrees.Keys);
            foreach (uint treeID in treeIDList)
            {
                DisconnectTree(treeID);
            }
        }

        private uint? AllocateTreeID()
        {
            for (uint offset = 0; offset < uint.MaxValue; offset++)
            {
                uint treeID = m_nextTreeID + offset;
                if (treeID == 0 || treeID == 0xFFFFFFFF)
                {
                    continue;
                }

                if (!m_connectedTrees.ContainsKey(treeID))
                {
                    m_nextTreeID = treeID + 1;
                    return treeID;
                }
            }

            return null;
        }

        // VolatileFileID MUST be unique for all volatile handles within the scope of a session
        private ulong? AllocateVolatileFileID()
        {
            for (ulong offset = 0; offset < ulong.MaxValue; offset++)
            {
                ulong volatileFileID = m_nextVolatileFileID + offset;
                if (volatileFileID == 0 || volatileFileID == 0xFFFFFFFFFFFFFFFF)
                {
                    continue;
                }

                if (!m_openFiles.ContainsKey(volatileFileID))
                {
                    m_nextVolatileFileID = volatileFileID + 1;
                    return volatileFileID;
                }
            }

            return null;
        }
    }
}
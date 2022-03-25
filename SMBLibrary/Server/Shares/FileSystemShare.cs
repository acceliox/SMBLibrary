/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace SMBLibrary.Server
{
    public class FileSystemShare : ISMBShare
    {
        public FileSystemShare(string shareName, INTFileStore fileSystem) : this(shareName, fileSystem, CachingPolicy.ManualCaching)
        {
        }

        public FileSystemShare(string shareName, INTFileStore fileSystem, CachingPolicy cachingPolicy)
        {
            Name = shareName;
            FileStore = fileSystem;
            CachingPolicy = cachingPolicy;
        }

        public CachingPolicy CachingPolicy { get; }

        public event EventHandler<AccessRequestArgs> AccessRequested;

        public bool HasReadAccess(SecurityContext securityContext, string path)
        {
            return HasAccess(securityContext, path, FileAccess.Read);
        }

        public bool HasWriteAccess(SecurityContext securityContext, string path)
        {
            return HasAccess(securityContext, path, FileAccess.Write);
        }

        public bool HasAccess(SecurityContext securityContext, string path, FileAccess requestedAccess)
        {
            // To be thread-safe we must capture the delegate reference first
            EventHandler<AccessRequestArgs> handler = AccessRequested;
            if (handler != null)
            {
                AccessRequestArgs args = new AccessRequestArgs(securityContext.UserName, path, requestedAccess, securityContext.MachineName, securityContext.ClientEndPoint);
                handler(this, args);
                return args.Allow;
            }

            return true;
        }

        public string Name { get; }

        public INTFileStore FileStore { get; }
    }
}
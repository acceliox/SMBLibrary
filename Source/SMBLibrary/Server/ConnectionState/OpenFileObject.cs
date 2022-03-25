/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace SMBLibrary.Server
{
    internal class OpenFileObject
    {
        public OpenFileObject(uint treeID, string shareName, string path, object handle, FileAccess fileAccess)
        {
            TreeID = treeID;
            ShareName = shareName;
            Path = path;
            Handle = handle;
            FileAccess = fileAccess;
            OpenedDT = DateTime.UtcNow;
        }

        public uint TreeID { get; }

        public string ShareName { get; }

        public string Path { get; set; }

        public object Handle { get; }

        public FileAccess FileAccess { get; }

        public DateTime OpenedDT { get; }
    }
}
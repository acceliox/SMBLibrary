/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.20 - FileInternalInformation
    /// </summary>
    public class FileInternalInformation : FileInformation
    {
        public const int FixedLength = 8;

        public long IndexNumber;

        public FileInternalInformation()
        {
        }

        public FileInternalInformation(byte[] buffer, int offset)
        {
            IndexNumber = LittleEndianConverter.ToInt64(buffer, offset + 0);
        }

        public override FileInformationClass FileInformationClass => FileInformationClass.FileInternalInformation;

        public override int Length => FixedLength;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteInt64(buffer, offset + 0, IndexNumber);
        }
    }
}
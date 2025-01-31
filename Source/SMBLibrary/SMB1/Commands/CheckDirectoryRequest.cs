/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_CHECK_DIRECTORY Request
    /// </summary>
    public class CheckDirectoryRequest : SMB1Command
    {
        public const byte SupportedBufferFormat = 0x04;

        // Data:
        public byte BufferFormat;
        public string DirectoryName; // SMB_STRING

        public CheckDirectoryRequest()
        {
            BufferFormat = SupportedBufferFormat;
            DirectoryName = string.Empty;
        }

        public CheckDirectoryRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            BufferFormat = ByteReader.ReadByte(SMBData, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }

            DirectoryName = SMB1Helper.ReadSMBString(SMBData, 1, isUnicode);
        }


        public override CommandName CommandName => CommandName.SMB_COM_CHECK_DIRECTORY;

        public override byte[] GetBytes(bool isUnicode)
        {
            int length = 1;
            if (isUnicode)
            {
                length += DirectoryName.Length * 2 + 2;
            }
            else
            {
                length += DirectoryName.Length + 1;
            }

            SMBData = new byte[1 + length];
            ByteWriter.WriteByte(SMBData, 0, BufferFormat);
            SMB1Helper.WriteSMBString(SMBData, 1, isUnicode, DirectoryName);

            return base.GetBytes(isUnicode);
        }
    }
}
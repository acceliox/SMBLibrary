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
    /// [MS-FSCC] 2.5.10 - FileFsDeviceInformation
    /// </summary>
    public class FileFsDeviceInformation : FileSystemInformation
    {
        public const int FixedLength = 8;

        public DeviceType DeviceType;
        public DeviceCharacteristics Characteristics;

        public FileFsDeviceInformation()
        {
        }

        public FileFsDeviceInformation(byte[] buffer, int offset)
        {
            DeviceType = (DeviceType)LittleEndianConverter.ToUInt32(buffer, offset + 0);
            Characteristics = (DeviceCharacteristics)LittleEndianConverter.ToUInt32(buffer, offset + 4);
        }

        public override FileSystemInformationClass FileSystemInformationClass => FileSystemInformationClass.FileFsDeviceInformation;

        public override int Length => FixedLength;

        public override void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, (uint)DeviceType);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)Characteristics);
        }
    }
}
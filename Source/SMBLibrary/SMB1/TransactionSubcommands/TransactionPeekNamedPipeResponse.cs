/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_PEEK_NMPIPE Response
    /// </summary>
    public class TransactionPeekNamedPipeResponse : TransactionSubcommand
    {
        public const int ParametersLength = 6;

        // Parameters:
        public ushort ReadDataAvailable;
        public ushort MessageBytesLength;

        public NamedPipeState NamedPipeState;

        // Data:
        public byte[] ReadData;

        public TransactionPeekNamedPipeResponse()
        {
        }

        public TransactionPeekNamedPipeResponse(byte[] parameters, byte[] data)
        {
            ReadDataAvailable = LittleEndianConverter.ToUInt16(parameters, 0);
            MessageBytesLength = LittleEndianConverter.ToUInt16(parameters, 2);
            NamedPipeState = (NamedPipeState)LittleEndianConverter.ToUInt16(parameters, 4);

            ReadData = data;
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_PEEK_NMPIPE;

        public override byte[] GetParameters()
        {
            byte[] parameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(parameters, 0, ReadDataAvailable);
            LittleEndianWriter.WriteUInt16(parameters, 2, MessageBytesLength);
            LittleEndianWriter.WriteUInt16(parameters, 4, (ushort)NamedPipeState);
            return parameters;
        }

        public override byte[] GetData(bool isUnicode)
        {
            return ReadData;
        }
    }
}
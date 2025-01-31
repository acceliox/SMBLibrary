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
    /// TRANS_SET_NMPIPE_STATE Request
    /// </summary>
    public class TransactionSetNamedPipeStateRequest : TransactionSubcommand
    {
        // Setup:
        public ushort FID;

        // Parameters:
        public PipeState PipeState;

        public TransactionSetNamedPipeStateRequest()
        {
        }

        public TransactionSetNamedPipeStateRequest(byte[] setup, byte[] parameters)
        {
            FID = LittleEndianConverter.ToUInt16(setup, 2);

            PipeState = (PipeState)LittleEndianConverter.ToUInt16(parameters, 0);
        }

        public override TransactionSubcommandName SubcommandName => TransactionSubcommandName.TRANS_SET_NMPIPE_STATE;

        public override byte[] GetSetup()
        {
            byte[] setup = new byte[4];
            LittleEndianWriter.WriteUInt16(setup, 0, (ushort)SubcommandName);
            LittleEndianWriter.WriteUInt16(setup, 2, FID);
            return setup;
        }

        public override byte[] GetParameters()
        {
            return LittleEndianConverter.GetBytes((ushort)PipeState);
        }
    }
}
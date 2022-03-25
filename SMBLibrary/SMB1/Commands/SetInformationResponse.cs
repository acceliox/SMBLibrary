/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_SET_INFORMATION Response
    /// </summary>
    public class SetInformationResponse : SMB1Command
    {
        public SetInformationResponse()
        {
        }

        public SetInformationResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
        }

        public override CommandName CommandName => CommandName.SMB_COM_SET_INFORMATION;

        public override byte[] GetBytes(bool isUnicode)
        {
            return base.GetBytes(isUnicode);
        }
    }
}
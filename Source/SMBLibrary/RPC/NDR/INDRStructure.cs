/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.RPC
{
    /// <summary>
    /// Serializable Structure / Union / Array
    /// </summary>
    public interface INDRStructure
    {
        void Read(NDRParser parser);
        void Write(NDRWriter writer);
    }
}
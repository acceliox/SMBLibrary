/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using Utilities;

namespace SMBLibrary.NetBios
{
    public class NBTConnectionReceiveBuffer
    {
        private int m_readOffset;
        private int m_bytesInBuffer;
        private int? m_packetLength;

        public NBTConnectionReceiveBuffer() : this(SessionPacket.MaxSessionPacketLength)
        {
        }

        /// <param name="bufferLength">Must be large enough to hold the largest possible NBT packet</param>
        public NBTConnectionReceiveBuffer(int bufferLength)
        {
            if (bufferLength < SessionPacket.MaxSessionPacketLength)
            {
                throw new ArgumentException("bufferLength must be large enough to hold the largest possible NBT packet");
            }

            Buffer = new byte[bufferLength];
        }

        public byte[] Buffer { get; private set; }

        public int WriteOffset => m_readOffset + m_bytesInBuffer;

        public int BytesInBuffer => m_bytesInBuffer;

        public int AvailableLength => Buffer.Length - (m_readOffset + m_bytesInBuffer);

        public void IncreaseBufferSize(int bufferLength)
        {
            byte[] buffer = new byte[bufferLength];
            if (m_bytesInBuffer > 0)
            {
                Array.Copy(Buffer, m_readOffset, buffer, 0, m_bytesInBuffer);
                m_readOffset = 0;
            }

            Buffer = buffer;
        }

        public void SetNumberOfBytesReceived(int numberOfBytesReceived)
        {
            m_bytesInBuffer += numberOfBytesReceived;
        }

        public bool HasCompletePacket()
        {
            if (m_bytesInBuffer >= 4)
            {
                if (!m_packetLength.HasValue)
                {
                    m_packetLength = SessionPacket.GetSessionPacketLength(Buffer, m_readOffset);
                }

                return m_bytesInBuffer >= m_packetLength.Value;
            }

            return false;
        }

        /// <summary>
        /// HasCompletePacket must be called and return true before calling DequeuePacket
        /// </summary>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SessionPacket DequeuePacket()
        {
            SessionPacket packet;
            try
            {
                packet = SessionPacket.GetSessionPacket(Buffer, m_readOffset);
            }
            catch (IndexOutOfRangeException ex)
            {
                throw new InvalidDataException("Invalid NetBIOS session packet", ex);
            }

            RemovePacketBytes();
            return packet;
        }

        /// <summary>
        /// HasCompletePDU must be called and return true before calling DequeuePDUBytes
        /// </summary>
        public byte[] DequeuePacketBytes()
        {
            byte[] packetBytes = ByteReader.ReadBytes(Buffer, m_readOffset, m_packetLength.Value);
            RemovePacketBytes();
            return packetBytes;
        }

        private void RemovePacketBytes()
        {
            m_bytesInBuffer -= m_packetLength.Value;
            if (m_bytesInBuffer == 0)
            {
                m_readOffset = 0;
                m_packetLength = null;
            }
            else
            {
                m_readOffset += m_packetLength.Value;
                m_packetLength = null;
                if (!HasCompletePacket())
                {
                    Array.Copy(Buffer, m_readOffset, Buffer, 0, m_bytesInBuffer);
                    m_readOffset = 0;
                }
            }
        }
    }
}
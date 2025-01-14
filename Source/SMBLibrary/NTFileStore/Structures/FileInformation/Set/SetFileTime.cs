/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all subsequent operations on the same file handle.
    /// </summary>
    public struct SetFileTime
    {
        public bool MustNotChange;
        private DateTime? m_time;

        public SetFileTime(bool mustNotChange)
        {
            MustNotChange = mustNotChange;
            m_time = null;
        }

        public SetFileTime(DateTime? time)
        {
            MustNotChange = false;
            m_time = time;
        }

        public DateTime? Time
        {
            get
            {
                if (MustNotChange)
                {
                    return null;
                }

                return m_time;
            }
            set
            {
                MustNotChange = false;
                m_time = value;
            }
        }

        public long ToFileTimeUtc()
        {
            if (MustNotChange)
            {
                return -1;
            }

            if (!m_time.HasValue)
            {
                return 0;
            }

            return Time.Value.ToFileTimeUtc();
        }

        public static SetFileTime FromFileTimeUtc(long span)
        {
            if (span > 0)
            {
                DateTime value = DateTime.FromFileTimeUtc(span);
                return new SetFileTime(value);
            }

            if (span == 0)
            {
                return new SetFileTime(false);
            }

            if (span == -1)
            {
                return new SetFileTime(true);
            }

            throw new InvalidDataException("Set FILETIME cannot be less than -1");
        }

        public static implicit operator DateTime?(SetFileTime setTime)
        {
            return setTime.Time;
        }

        public static implicit operator SetFileTime(DateTime? time)
        {
            return new SetFileTime(time);
        }
    }
}
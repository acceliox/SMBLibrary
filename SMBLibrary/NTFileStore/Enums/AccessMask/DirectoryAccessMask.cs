using System;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-SMB] 2.2.1.4.2 - Directory_Access_Mask
    /// [MS-SMB2] 2.2.13.1.2 - Directory_Access_Mask
    /// </summary>
    [Flags]
    public enum DirectoryAccessMask : uint
    {
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_ADD_FILE = 0x00000002,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }
}
namespace SMBLibrary.SMB1
{
    public enum CommandName : byte
    {
        SMB_COM_CREATE_DIRECTORY = 0x00,
        SMB_COM_DELETE_DIRECTORY = 0x01,
        SMB_COM_CLOSE = 0x04,
        SMB_COM_FLUSH = 0x05,
        SMB_COM_DELETE = 0x06,
        SMB_COM_RENAME = 0x07,
        SMB_COM_QUERY_INFORMATION = 0x08,
        SMB_COM_SET_INFORMATION = 0x09,
        SMB_COM_READ = 0x0A,
        SMB_COM_WRITE = 0x0B,
        SMB_COM_CHECK_DIRECTORY = 0x10,
        SMB_COM_WRITE_RAW = 0x1D,
        SMB_COM_WRITE_COMPLETE = 0x20, // Write RAW final response
        SMB_COM_SET_INFORMATION2 = 0x22,
        SMB_COM_LOCKING_ANDX = 0x24,
        SMB_COM_TRANSACTION = 0x25,
        SMB_COM_TRANSACTION_SECONDARY = 0x26,
        SMB_COM_ECHO = 0x2B,
        SMB_COM_OPEN_ANDX = 0x2D,
        SMB_COM_READ_ANDX = 0x2E,
        SMB_COM_WRITE_ANDX = 0x2F,
        SMB_COM_TRANSACTION2 = 0x32,
        SMB_COM_TRANSACTION2_SECONDARY = 0x33,
        SMB_COM_FIND_CLOSE2 = 0x34,
        SMB_COM_TREE_DISCONNECT = 0x71,
        SMB_COM_NEGOTIATE = 0x72,
        SMB_COM_SESSION_SETUP_ANDX = 0x73,
        SMB_COM_LOGOFF_ANDX = 0x74,
        SMB_COM_TREE_CONNECT_ANDX = 0x75,
        SMB_COM_NT_TRANSACT = 0xA0,
        SMB_COM_NT_TRANSACT_SECONDARY = 0xA1,
        SMB_COM_NT_CREATE_ANDX = 0xA2,
        SMB_COM_NT_CANCEL = 0xA4,
        SMB_COM_NO_ANDX_COMMAND = 0xFF
    }
}
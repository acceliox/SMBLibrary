using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_WRITE Response.
    /// This command is obsolete.
    /// Windows NT4 SP6 will send this command with empty data for some reason.
    /// </summary>
    public class WriteResponse : SMB1Command
    {
        public const int ParametersLength = 2;

        // Parameters:
        public ushort CountOfBytesWritten;

        public WriteResponse()
        {
        }

        public WriteResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            CountOfBytesWritten = LittleEndianConverter.ToUInt16(SMBParameters, 0);
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE;

        public override byte[] GetBytes(bool isUnicode)
        {
            SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(SMBParameters, 0, CountOfBytesWritten);

            return base.GetBytes(isUnicode);
        }
    }
}
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SMBLibrary.Client;
using SMBLibrary.Services;

namespace SMBLibrary
{
    public class NamedPipeStore : INTFileStore
    {
        public NamedPipeStore(List<RemoteService> services)
        {
        }

        public Task<StatusResult<object?, FileStatus>> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            throw new NotImplementedException();
        }

        public Task<NTStatus> CloseFile(object handle)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<byte[]?>> ReadFile(object handle, long offset, int maxCount)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<int>> WriteFile(object handle, long offset, byte[] data)
        {
            throw new NotImplementedException();
        }

        public Task<NTStatus> FlushFileBuffers(object handle)
        {
            throw new NotImplementedException();
        }

        public Task<NTStatus> LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public Task<NTStatus> UnlockFile(object handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<FileInformation?>> GetFileInformation(object handle, FileInformationClass informationClass)
        {
            throw new NotImplementedException();
        }

        public Task<NTStatus> SetFileInformation(object handle, FileInformation information)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<FileSystemInformation?>> GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            throw new NotImplementedException();
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<SecurityDescriptor?>> GetSecurityInformation(object handle, SecurityInformation securityInformation)
        {
            throw new NotImplementedException();
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            throw new NotImplementedException();
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public Task<StatusResult<byte[]?>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength)
        {
            throw new NotImplementedException();
        }
    }
}
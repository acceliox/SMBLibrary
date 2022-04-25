/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SMBLibrary.SMB2;

namespace SMBLibrary.Client
{
    // ReSharper disable once InconsistentNaming
    public class SMB2FileStore : ISMBFileStore
    {
        private const int BytesPerCredit = 65536;

        private readonly SMB2Client _client;
        private readonly uint _treeId;
        private readonly bool _encryptShareData;

        public SMB2FileStore(SMB2Client client, uint treeId, bool encryptShareData)
        {
            _client = client;
            _treeId = treeId;
            _encryptShareData = encryptShareData;
        }

        public async Task<StatusResult<object?, FileStatus>> CreateFile(string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            object? handle = null;
            FileStatus fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            CreateRequest request = new CreateRequest
            {
                Name = path,
                DesiredAccess = desiredAccess,
                FileAttributes = fileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                ImpersonationLevel = ImpersonationLevel.Impersonation
            };
            TrySendCommand(request);

            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    CreateResponse createResponse = (CreateResponse)response;
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                }

                return new StatusResult<object?, FileStatus>(handle, fileStatus, response.Header.Status);
            }

            return new StatusResult<object?, FileStatus>(handle, fileStatus, NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<NTStatus> CloseFile(object handle)
        {
            CloseRequest request = new CloseRequest
            {
                FileId = (FileID)handle
            };
            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<StatusResult<byte[]?>> ReadFile(object handle, long offset, int maxCount)
        {
            byte[]? data = null;
            ReadRequest request = new ReadRequest
            {
                Header =
                {
                    CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit)
                },
                FileId = (FileID)handle,
                Offset = (ulong)offset,
                ReadLength = (uint)maxCount
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    data = ((ReadResponse)response).Data;
                }

                return new StatusResult<byte[]?>(data, response.Header.Status);
            }

            return new StatusResult<byte[]?>(data, NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<StatusResult<int>> WriteFile(object handle, long offset, byte[] data)
        {
            int numberOfBytesWritten = 0;
            WriteRequest request = new WriteRequest
            {
                Header =
                {
                    CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit)
                },
                FileId = (FileID)handle,
                Offset = (ulong)offset,
                Data = data
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    numberOfBytesWritten = (int)((WriteResponse)response).Count;
                }

                return new StatusResult<int>(numberOfBytesWritten, response.Header.Status);
            }

            return new StatusResult<int>(numberOfBytesWritten, NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<NTStatus> FlushFileBuffers(object handle)
        {
            var request = new FlushRequest
            {
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is FlushResponse)
                {
                    return response.Header.Status;
                }
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public Task<NTStatus> LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            throw new NotImplementedException();
        }

        public Task<NTStatus> UnlockFile(object handle, long byteOffset, long length)
        {
            throw new NotImplementedException();
        }

        public async Task<StatusResult<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass)
        {
            var result = new List<QueryDirectoryFileInformation>();
            var request = new QueryDirectoryRequest
            {
                Header =
                {
                    CreditCharge = (ushort)Math.Ceiling((double)_client.MaxTransactSize / BytesPerCredit)
                },
                FileInformationClass = informationClass,
                Reopen = true,
                FileId = (FileID)handle,
                OutputBufferLength = _client.MaxTransactSize,
                FileName = fileName
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse)
                {
                    List<QueryDirectoryFileInformation> page = ((QueryDirectoryResponse)response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    TrySendCommand(request);
                    response = await _client.WaitForCommand(request.MessageID);
                }

                return new StatusResult<List<QueryDirectoryFileInformation>>(result, response.Header.Status);
            }

            return new StatusResult<List<QueryDirectoryFileInformation>>(result, NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<StatusResult<FileInformation?>> GetFileInformation(object handle, FileInformationClass informationClass)
        {
            FileInformation? result = null;
            var request = new QueryInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }

                return new StatusResult<FileInformation?>(result, response.Header.Status);
            }

            return new StatusResult<FileInformation?>(result, NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<NTStatus> SetFileInformation(object handle, FileInformation information)
        {
            SetInfoRequest request = new SetInfoRequest
            {
                InfoType = InfoType.File,
                FileInformationClass = information.FileInformationClass,
                FileId = (FileID)handle
            };
            request.SetFileInformation(information);

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public async Task<StatusResult<FileSystemInformation?>> GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            FileSystemInformation? result = null;

            var writeFileResult = await CreateFile(string.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            var status = writeFileResult.Status;

            if (status != NTStatus.STATUS_SUCCESS)
            {
                return new StatusResult<FileSystemInformation?>(result, status);
            }

            object? fileHandle = writeFileResult.Result1;
            FileStatus fileStatus = writeFileResult.Result2;

            var getFileSystemInformationResult = await GetFileSystemInformation(fileHandle, informationClass);
            status = getFileSystemInformationResult.Status;
            result = getFileSystemInformationResult.Result;

            await CloseFile(fileHandle);
            return new StatusResult<FileSystemInformation?>(result, status);
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public async Task<StatusResult<SecurityDescriptor?>> GetSecurityInformation(object handle, SecurityInformation securityInformation)
        {
            SecurityDescriptor? result = null;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.Security,
                SecurityInformation = securityInformation,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetSecurityInformation();
                }

                return new StatusResult<SecurityDescriptor?>(result, response.Header.Status);
            }

            return new StatusResult<SecurityDescriptor?>(result, NTStatus.STATUS_INVALID_SMB);
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public async Task<StatusResult<byte[]?>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength)
        {
            byte[]? output = null;
            var request = new IOCtlRequest
            {
                Header =
                {
                    CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit)
                },
                CtlCode = ctlCode,
                IsFSCtl = true,
                FileId = (FileID)handle,
                Input = input,
                MaxOutputResponse = (uint)maxOutputLength
            };
            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    output = ((IOCtlResponse)response).Output;
                }

                return new StatusResult<byte[]?>(output, response.Header.Status);
            }

            return new StatusResult<byte[]?>(output, NTStatus.STATUS_INVALID_SMB);
        }

        public async Task<NTStatus> Disconnect()
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public uint MaxReadSize => _client.MaxReadSize;

        public uint MaxWriteSize => _client.MaxWriteSize;

        private async Task<StatusResult<FileSystemInformation?>> GetFileSystemInformation(object handle, FileSystemInformationClass informationClass)
        {
            FileSystemInformation? result = null;
            QueryInfoRequest request = new QueryInfoRequest
            {
                InfoType = InfoType.FileSystem,
                FileSystemInformationClass = informationClass,
                OutputBufferLength = 4096,
                FileId = (FileID)handle
            };

            TrySendCommand(request);
            var response = await _client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    result = ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                }

                return new StatusResult<FileSystemInformation?>(result, response.Header.Status);
            }

            return new StatusResult<FileSystemInformation?>(result, NTStatus.STATUS_INVALID_SMB);
        }

        private void TrySendCommand(SMB2Command request)
        {
            request.Header.TreeID = _treeId;
            _client.TrySendCommand(request, _encryptShareData);
        }

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            return createAction switch
            {
                CreateAction.FILE_SUPERSEDED => FileStatus.FILE_SUPERSEDED,
                CreateAction.FILE_OPENED => FileStatus.FILE_OPENED,
                CreateAction.FILE_CREATED => FileStatus.FILE_CREATED,
                CreateAction.FILE_OVERWRITTEN => FileStatus.FILE_OVERWRITTEN,
                _ => FileStatus.FILE_OPENED
            };
        }
    }
}
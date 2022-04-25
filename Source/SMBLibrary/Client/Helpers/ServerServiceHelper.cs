/* Copyright (C) 2014-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Threading.Tasks;
using SMBLibrary.RPC;
using SMBLibrary.Services;
using Utilities;

namespace SMBLibrary.Client
{
    public class ServerServiceHelper
    {
        public static Task<StatusResult<List<string>?>> ListShares(INTFileStore namedPipeShare, ShareType? shareType)
        {
            return ListShares(namedPipeShare, "*", shareType);
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public static async Task<StatusResult<List<string>?>> ListShares(INTFileStore namedPipeShare, string serverName, ShareType? shareType)
        {
            var bindPipeResult = await NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion);
            object? pipeHandle = bindPipeResult.Result1;
            int maxTransmitFragmentSize = bindPipeResult.Result2;

            var status = bindPipeResult.Status;
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return new StatusResult<List<string>?>(null, status);
            }

            NetrShareEnumRequest shareEnumRequest = new NetrShareEnumRequest();
            shareEnumRequest.InfoStruct = new ShareEnum();
            shareEnumRequest.InfoStruct.Level = 1;
            shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
            shareEnumRequest.PreferedMaximumLength = uint.MaxValue;
            shareEnumRequest.ServerName = @"\\" + serverName;
            RequestPDU requestPDU = new RequestPDU();
            requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            requestPDU.OpNum = (ushort)ServerServiceOpName.NetrShareEnum;
            requestPDU.Data = shareEnumRequest.GetBytes();
            requestPDU.AllocationHint = (uint)requestPDU.Data.Length;
            byte[] input = requestPDU.GetBytes();
            int maxOutputLength = maxTransmitFragmentSize;

            var deviceIoCtrl = await namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, maxOutputLength);
            byte[]? output = deviceIoCtrl.Result;
            status = deviceIoCtrl.Status;

            if (status != NTStatus.STATUS_SUCCESS)
            {
                return new StatusResult<List<string>?>(null, status);
            }

            var responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                status = NTStatus.STATUS_NOT_SUPPORTED;
                return new StatusResult<List<string>?>(null, status);
            }

            byte[] responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                var readFileResult = await namedPipeShare.ReadFile(pipeHandle, 0, maxOutputLength);
                output = readFileResult.Result;
                status = readFileResult.Status;
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return new StatusResult<List<string>?>(null, status);
                }

                responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return new StatusResult<List<string>?>(null, status);
                }

                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }

            await namedPipeShare.CloseFile(pipeHandle);
            NetrShareEnumResponse shareEnumResponse = new NetrShareEnumResponse(responseData);
            ShareInfo1Container shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
            if (shareInfo1 == null || shareInfo1.Entries == null)
            {
                if (shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED)
                {
                    status = NTStatus.STATUS_ACCESS_DENIED;
                }
                else
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                }

                return new StatusResult<List<string>?>(null, status);
            }

            List<string> result = new List<string>();
            foreach (ShareInfo1Entry entry in shareInfo1.Entries)
            {
                if (!shareType.HasValue || shareType.Value == entry.ShareType.ShareType)
                {
                    result.Add(entry.NetName.Value);
                }
            }

            return new StatusResult<List<string>?>(result, status);
        }
    }
}
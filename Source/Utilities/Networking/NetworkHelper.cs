using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Utilities.Networking
{
    public static class NetworkHelper
    {
        public static IPAddress GetIpv4(string serverName)
        {
            if (IPAddress.TryParse(serverName, out var ipAddress))
            {
                return ipAddress;
            }

            IPHostEntry hostEntry = Dns.GetHostEntry(serverName);
            if (hostEntry.AddressList.Length == 0)
            {
                throw new Exception($"Cannot resolve host name {serverName} to an IP address");
            }

            var v4Address = hostEntry.AddressList.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
            if (v4Address != null)
            {
                return v4Address;
            }

            return hostEntry.AddressList[0];
        }
    }
}
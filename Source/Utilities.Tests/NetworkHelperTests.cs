using System.Net;
using FluentAssertions;
using Utilities.Networking;
using Xunit;

namespace Utilities.Tests
{
    public class NetworkHelperTests
    {
        [Fact]
        public void GetIpFromDomain_Localhost_TranslatesCorrectly()
        {
            // arrange
            var server = "localhost";

            // act
            var result = NetworkHelper.GetIpv4(server);

            // assert
            result.Should().BeEquivalentTo(IPAddress.Parse("127.0.0.1"));
        }

        [Fact]
        public void GetIpFromDomain_WithIp_NoDnsLookup()
        {
            // arrange
            var server = "127.0.0.1";

            // act
            var result = NetworkHelper.GetIpv4(server);

            // assert
            result.Should().BeEquivalentTo(IPAddress.Parse("127.0.0.1"));
        }
    }
}
using ATrustIdentRecord.DataModel;
using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace ATrustIdentRecord
{
    public static class IdentRecordApi
    {
        private const int DEFAULT_BKU_Timeout = 70000;
        private static HttpClientHandler handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            Proxy = null,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };

        private static HttpClient httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(DEFAULT_BKU_Timeout)
        };


        public static async Task<(bool, string)> Upload(byte[] identRecord, string uri)
        {

            bool isV4 = uri.Contains("/v4");

            var postUri = new Uri(GetBaseUri(uri), "Identification");

            using (var content = new ByteArrayContent(identRecord))
            {
                content.Headers.ContentLength = identRecord.Length;

                using (var response = await httpClient.PostAsync(postUri, content))
                {
                    response.EnsureSuccessStatusCode();
                    if (isV4)
                    {
                        var stream = await response.Content.ReadAsStreamAsync();
                        var respObj = JsonSerializer.Deserialize<AddIdentrecordResponse>(stream);
                        return (true, respObj.nextUrl);
                    }
                    else
                    {
                        return (true, null); 
                    }
                }
            }
        }


        public static async Task<byte[]> LoadEncryptionCertificate(string uri)
        {
            var certficiateUri = new Uri(GetBaseUri(uri), "Certificate");
            using (var response = await httpClient.GetAsync(certficiateUri))
            {
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsByteArrayAsync();
            }
        }


        private static Uri GetBaseUri(string uri)
        {
            if (uri.EndsWith("/Identification", StringComparison.InvariantCultureIgnoreCase))
            {
                uri = uri.Substring(0, uri.Length - 14);
            }
            else if (uri.EndsWith("/Certificate", StringComparison.InvariantCultureIgnoreCase))
            {
                uri = uri.Substring(0, uri.Length - 11);
            }
            else if (uri.EndsWith("/Certificate/PEM", StringComparison.InvariantCultureIgnoreCase))
            {
                uri = uri.Substring(0, uri.Length - 15);
            }

            if(!uri.EndsWith("/"))
            {
                uri += "/";
            }

            return new Uri(uri);
        }
    }
}

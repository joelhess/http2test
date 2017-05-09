using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace http2test
{
    class Program
    {
        static void Main(string[] args)
        {
            TestConnection();
            Console.ReadLine();
        }

        static async Task TestConnection()
        {
            using (var client = new HttpClient())
            {
                var request =
                    new HttpRequestMessage(HttpMethod.Get, "https://nghttp2.org") { Version = new Version(2, 0) };


                try
                {
                    var response = await client.SendAsync(request);
                    Console.WriteLine($"Http Status = {response.StatusCode}");
                    Console.WriteLine($"Http version = {response.Version}");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }

            }
        }
    }
}
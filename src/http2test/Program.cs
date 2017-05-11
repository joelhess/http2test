using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace http2test
{
    class Program
    {

		public static string issuerId = "3UTKTW44JW"; //This is the Apple Team Id
		public static string keyId = "XG76H7G3T4";

		public static string DevelopmentServerAddress = "api.development.push.apple.com:443";
		public static string ProductionServierAddress = "api.push.apple.com:443";

        static void Main(string[] args)
        {
            //createJwt();
            TestConnection().GetAwaiter().GetResult();
            Console.ReadLine();
        }

        static async Task TestConnection()
        {
            using (var client = new HttpClient())
            {
                var request =
                    new HttpRequestMessage(HttpMethod.Get, "https://nghttp2.org")//"https://api.development.push.apple.com/3/device/aaaa") 
                { Version = new Version(2, 0) };

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

        static void createJwt()
        {
            DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(1000);

            var claims = new[]
            {
                new Claim("kid", keyId),
                new Claim("alg", "ES256"),
				new Claim(JwtRegisteredClaimNames.Iss, issuerId),
				new Claim(JwtRegisteredClaimNames.Iat,
                          dateTimeOffset.ToUnixTimeSeconds().ToString(),
						  ClaimValueTypes.Integer64),
			};

			// Create the JWT security token and encode it.
			var jwt = new JwtSecurityToken(
				claims: claims
			//	notBefore: _jwtOptions.NotBefore,
			//	expires: _jwtOptions.Expiration,
				//signingCredentials: _jwtOptions.SigningCredentials)
            );

			var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

		}   

		/// <summary>
		/// Method returns ECDSA signed JWT token format, from json header, json payload and privateKey (pure string extracted from *.p8 file - PKCS#8 format)
		/// </summary>
		/// <param name="privateKey">ECDSA256 key</param>
		/// <param name="header">JSON header, i.e. "{\"alg\":\"ES256\" ,\"kid\":\"1234567899"\"}"</param>
		/// <param name="payload">JSON payload, i.e.  {\"iss\":\"MMMMMMMMMM"\",\"iat\":"122222222229"}"</param>
		/// <returns>base64url encoded JWT token</returns>
		public static string SignES256(string privateKey, string header, string payload)
		{
			CngKey key = CngKey.Import(
				Convert.FromBase64String(privateKey),
				CngKeyBlobFormat.Pkcs8PrivateBlob);

			using (ECDsaCng dsa = new ECDsaCng(key))
			{
                var unsignedJwtData =
                    System.Convert.ToBase64String(Encoding.UTF8.GetBytes(header)) + "." + System.Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
                var unsignedJwtDataBytes = Encoding.UTF8.GetBytes(unsignedJwtData);

                var signature =
                    dsa.SignData(unsignedJwtDataBytes, 0, unsignedJwtDataBytes.Length, HashAlgorithmName.SHA256 );
				return unsignedJwtData + "." + System.Convert.ToBase64String(signature);
			}
		}
    }
}
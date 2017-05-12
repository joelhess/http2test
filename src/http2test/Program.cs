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
            var keyFile = System.IO.File.ReadAllText("APNsAuthKey_XG76H7G3T4.p8");


            string issuerId = "3UTKTW44JW";

            var tokenHeader = "{\"alg\":\"ES256\" ,\"kid\":\"XG76H7G3T4\"}";
            var tokenPayload= "{\"iss\":\"" + issuerId + "\",\"iat\":\"" + ((Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds).ToString() + "\"}";

            var signage = SignES256(keyFile, tokenHeader, tokenPayload);

            //createJwt();
            TestConnection(signage).GetAwaiter().GetResult();
            Console.ReadLine();
        }

        static async Task TestConnection(string authToken = null)
        {
            using (var client = new HttpClient())
            {
                var request =
                    new HttpRequestMessage(HttpMethod.Post, "https://api.development.push.apple.com/3/device/08736017052ccdb6925c0be553967be120b0b07f05ff9de19d4f18c4e36c4e67") 
                    {
                        Version = new Version(2, 0)
                    };

                if (authToken != null)
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authToken);


                request.Headers.Add("apns-topic", "com.spok.notify");

                request.Content = new StringContent(" { \"aps\" : { \"alert\" : \"Hello\" } }");// "{ \"alert\" : \"You've Got Mail\"}");

                try
                {
                    var response = await client.SendAsync(request);
                    Console.WriteLine($"Http Status = {response.StatusCode}");
                    if (!response.IsSuccessStatusCode)
                        Console.WriteLine($"Response payload = {response.Content.ReadAsStringAsync().Result}");

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
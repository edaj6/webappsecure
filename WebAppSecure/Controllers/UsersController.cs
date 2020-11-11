using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using IdentityServer4.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace WebAppSecure.Controllers
{
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly ILogger<UsersController> logger;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration configuration;

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public UsersController(SignInManager<IdentityUser> signInManager,
            ILogger<UsersController> logger,
            UserManager<IdentityUser> userManager,
            IConfiguration configuration)
        {
            this.signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }


        [HttpPost("api/users/authenticate")]
        public async Task<object> Authenticate([FromBody] InputModel Input)
        {
            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                Microsoft.AspNetCore.Identity.SignInResult result =
                    await signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    logger.LogInformation("User logged in.");

                    IdentityUser userFromManager = await userManager.FindByNameAsync(Input.Email);
                    var token = generateJwtToken(userFromManager);
                    return Ok(new
                    {
                        username = userFromManager.UserName,
                        jwt = token
                    });
                }
                else
                {
                    return Unauthorized("Invalid login attempt.");
                }
            }

            return BadRequest("Error in input, please provide email and password");
        }

        [HttpGet("api/users/jwt")]
        public async Task<string> GetJwtAsync()
        {
            var token = await generateJwtToken(new IdentityUser { UserName = "ausername", Email = "a@email"});
            return token;
        }

        [HttpGet("api/users/publickey")]
        public async Task<KeyVaultKey> GetPublicKey()
        {
            return await GetPublicKeyVaultKey();
        }

        [HttpGet("api/users/publickeystring")]
        public async Task<string> GetPublicKeyString()
        {
            var key = await GetPublicKeyVaultKey();
            var publicKey = Convert.ToBase64String(key.Key.N);

            return publicKey;
        }

        private async Task<KeyVaultKey> GetPublicKeyVaultKey()
        {
            var keyClient = new KeyClient(
                new Uri("https://cleankey.vault.azure.net/"),
                new DefaultAzureCredential());

            var response = await keyClient.GetKeyAsync("CleanKey");
            return response.Value;
        }

        [HttpGet("api/users/validate/{jwt}")]
        public async Task<bool> ValidateJwt(string jwt)
        {
            KeyVaultKey key;
            string jsonString;

            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://api.github.com");
                client.DefaultRequestHeaders.Add("User-Agent", "Anything");
                
                //var response = client.GetAsync("https://identityloginapi.azurewebsites.net/api/users/publickey");

                var task = await client.GetAsync("https://identityloginapi.azurewebsites.net/api/users/publickeystring");
                jsonString = await task.Content.ReadAsStringAsync();

                //key = JsonConvert.DeserializeObject<KeyVaultKey>(jsonString);


            }
            
            var publicKey = Encoding.ASCII.GetBytes(jsonString);

            //var publicKey = jsonString.ToByteArray();  //key.Key.N;

            return myValidateToken(jwt, jsonString);

            var rsa = System.Security.Cryptography.RSA.Create();

            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(jsonString), out _);

            //rsa.ImportRSAPublicKey(publicKey, out _);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                //ValidIssuer = _settings.Issuer,
                //ValidAudience = _settings.Audience,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(jwt, validationParameters, out var validatedSecurityToken);
            }
            catch
            {
                return false;
            }

            return true;            
        }

        private bool myValidateToken(string token, string publicKeyString)
        {
            var publicKey = Encoding.ASCII.GetBytes(publicKeyString);  

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKey, out _);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                //ValidIssuer = _settings.Issuer,
                //ValidAudience = _settings.Audience,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
            }
            catch
            {
                return false;
            }

            return true;
        }


        //inspired by https://jasonwatmore.com/post/2019/10/11/aspnet-core-3-jwt-authentication-tutorial-with-example-api
        private async Task<string> generateJwtToken(IdentityUser user)
        {
            // generate token that is valid for 7 days
            //todo use refreshtoken, denne bør kun være gældende fx 10 min - auth as microservice: https://www.youtube.com/watch?v=SLc3cTlypwM&feature=youtu.be
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(configuration["Secret"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("id", user.Id),
                    new Claim("username", user.UserName),
                    new Claim("id", user.Email),
                    new Claim("roles", "changeitem")
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = "smartapp",                
                //SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var jwt = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);            
            var signed = await SignAndCreateJwtAsync(jwt);

            return signed;
        }

        private async Task<string> SignAndCreateJwtAsync(JwtSecurityToken jwt)
        {
            var algorithm = "RS256";//jwt.SignatureAlgorithm;

            var plaintext = $"{jwt.EncodedHeader}.{jwt.EncodedPayload}";
            byte[] hash;
            using (var hasher = CryptoHelper.GetHashAlgorithmForSigningAlgorithm(algorithm))
            {
                hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(plaintext));
            }
                        
            var cryptoClient = new CryptographyClient(
               new Uri("https://cleankey.vault.azure.net/keys/cleankey/82f7ce0323574ab4869565d3bc525793"),
               new DefaultAzureCredential());

            try
            {
                //jwt.SignatureAlgorithm
                var signResult = await cryptoClient.SignAsync(new SignatureAlgorithm(algorithm), hash);
                return $"{plaintext}.{Base64UrlTextEncoder.Encode(signResult.Signature)}";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}

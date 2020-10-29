using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
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
                //if (result.RequiresTwoFactor)
                //{
                //    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                //}
                //if (result.IsLockedOut)
                //{
                //    logger.LogWarning("User account locked out.");
                //    return RedirectToPage("./Lockout");
                //}
                else
                {
                    return Unauthorized("Invalid login attempt.");                   
                }
            }

            return BadRequest("Error in input, please provide email and password");            
        }

        //inspired by https://jasonwatmore.com/post/2019/10/11/aspnet-core-3-jwt-authentication-tutorial-with-example-api
        private string generateJwtToken(IdentityUser user)
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
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}

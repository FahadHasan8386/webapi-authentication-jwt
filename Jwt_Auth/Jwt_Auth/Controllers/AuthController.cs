using Jwt_Auth.Entities;
using Jwt_Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Jwt_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IConfiguration configuration) : Controller
    {
        public static User user = new();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto userDto)
        {
            var hasedPassword = new PasswordHasher<User>().HashPassword(user , userDto.Password);

            user.Username = userDto.UserName;
            user.PasswordHash = hasedPassword;

            return Ok(user);
        }

        [HttpPost("Login")]
        public ActionResult<string> Login(UserDto request)
        {
            if(user.Username != request.UserName)
            {
                return BadRequest("User not found");
            }
            if(new PasswordHasher<User>().VerifyHashedPassword(user , user.PasswordHash , request.Password) == PasswordVerificationResult.Failed)
            {
                return BadRequest("Wrong Password");
            }
            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            var tokenKey = configuration.GetValue<string>("AppSettings:Token");

            if (string.IsNullOrEmpty(tokenKey))
            {
                throw new Exception("JWT Token key is missing in configuration!");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(tokenKey)
            );

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescription = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescription);
        }

    }
}

using Jwt_Auth.Entities;
using Jwt_Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Jwt_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
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
    }
}

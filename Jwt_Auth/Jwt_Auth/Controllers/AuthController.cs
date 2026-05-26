using Jwt_Auth.Entities;
using Jwt_Auth.Models;
using Jwt_Auth.Services;
using Microsoft.AspNetCore.Mvc;

namespace Jwt_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto)
        {
            var user = await authService.RegisterAsync(userDto);

            if (user == null)
            {
                return BadRequest("User already exists");
            }

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);

            if (token == null)
            {
                return BadRequest("Invalid username or password");
            }

            return Ok(token);
        }
    }
}
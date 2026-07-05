using Jwt_Auth.Entities;
using Jwt_Auth.Models;
using Jwt_Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

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
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var result = await authService.LoginAsync(request);

            if (result == null)
            {
                return BadRequest("Invalid username or password");
            }

            return Ok(result);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if(userIdClaim == null)
            {
                return Unauthorized();
            }
            var success = await authService.LogoutAsync(Guid.Parse(userIdClaim.Value));
            if (!success)
                return NotFound();

            return Ok("Logged out successfully.");
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokenAsync(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null)
                return Unauthorized("Invalid refresh token.");

            return Ok(result);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("Yor are authenticated .");
        }


        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("Yor are admin .");
        }
    }
}
using Azure.Core;
using Jwt_Auth.Data;
using Jwt_Auth.Entities;
using Jwt_Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Jwt_Auth.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration): IAuthService
    {

        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
        {
            var user = await context.Users
                .FirstOrDefaultAsync(u => u.Username == request.UserName);

            // user null check
            if (user == null)
            {
                return null;
            }

            // password verify
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) 
                == PasswordVerificationResult.Failed)
            {
                return null;
            }

            return await CreateTokenResponse(user);
        }
        private async Task<TokenResponseDto> CreateTokenResponse(User user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
            };
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            // username exists check
            if (await context.Users.AnyAsync(u => u.Username == request.UserName))
            {
                return null;
            }

            var user = new User();

            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);

            user.Username = request.UserName;
            user.PasswordHash = hashedPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            var result = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);

            if(result is null)
            {
                return null;
            }
            return await CreateTokenResponse(result);
        }

        public async Task<User?> ValidateRefreshTokenAsync(Guid userId , string refreshToken)
        {
            var result = await context.Users.FindAsync(userId);
            if(result is null || result.RefreshToken != refreshToken || result.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }
            return result;
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await context.SaveChangesAsync();
            return refreshToken;
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        public async Task<bool> LogoutAsync(Guid userId)
        {
            var result = await context.Users.FindAsync(userId);

            if(result == null)
            {
                return false;
            }
            result.RefreshToken = null;
            result.RefreshTokenExpiryTime = null;

            await context.SaveChangesAsync();

            return true;
        }
    }
}
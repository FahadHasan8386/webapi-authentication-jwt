using Jwt_Auth.Entities;
using Jwt_Auth.Models;

namespace Jwt_Auth.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<string?> LoginAsync(UserDto request);
        
    }
}

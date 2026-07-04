namespace Jwt_Auth.Models
{
    public class RefreshTokenRequestDto
    {
        public Guid UserId {  get; set; }
        public required string RefreshToken { get; set; }   

    }
}

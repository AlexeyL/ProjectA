using System.Text.Json.Serialization;

namespace AuthService.Application.Common.DTOs
{
    public class AuthResponse
    {
        public int UserId { get; set; }

        public string UserName { get; set; }
        
        public string AccessToken { get; set; }
       
        [JsonIgnore]
        public string RefreshToken { get; set; }

        public AuthResponse(int userId, string userName, string accessToken, string refreshToken)
        {
            UserId = userId;
            UserName = userName;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }
    }
}

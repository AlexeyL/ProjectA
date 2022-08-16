using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace AuthService.Domain.Entities
{
    public class User: BaseEntity
    {
        [Required]
        public string FirstName { get; set; } = string.Empty;
        
        [Required]
        public string LastName { get; set; } = string.Empty;
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        [JsonIgnore]
        public string Password { get; set; } = string.Empty;
        
        [JsonIgnore]
        public string PasswordHash { get; set; }
        
        public bool Disabled { get; set; } = false;
        
        [JsonIgnore]
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}

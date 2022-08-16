namespace AuthService.Domain.Entities
{
    public class RefreshToken : BaseEntity
    {
        public string Token { get; set; }
        
        public string CreatedByIp { get; set; }
        
        public DateTime Expires { get; set; }
        
        public bool IsExpired => DateTime.UtcNow >= Expires;
        
        public int UserId { get; set; }
        
        public User User { get; set; }
    }
}

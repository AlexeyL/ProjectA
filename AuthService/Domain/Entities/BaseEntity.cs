using System.ComponentModel.DataAnnotations;

namespace AuthService.Domain.Entities
{
    public abstract class BaseEntity
    {
        [Key]
        public int Id { get; set; }
        
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        
        public DateTime ModifiedDate { get; set; } = DateTime.Now;
    }
}

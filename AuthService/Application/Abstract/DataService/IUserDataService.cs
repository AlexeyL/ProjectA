using AuthService.Domain.Entities;

namespace AuthService.Application.Abstract.DataService
{
    public interface IUserDataService
    {
        Task<User> GetUserByEmailAsync(string email);

        Task<IEnumerable<string>> GetUserRolesAsync(int userId);

        Task<User> GetUserByRefreshTokenAsync(string refreshToken);

        Task<bool> SaveRefreshToken(int userId, RefreshToken refreshToken);

        Task<bool> DeleteRefreshToken(RefreshToken refreshToken);
    }
}

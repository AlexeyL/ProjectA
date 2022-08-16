using AuthService.Application.Abstract.DataService;
using AuthService.Domain.Entities;

namespace AuthService.Persistence.DataServices
{
    public class UserDataService: IUserDataService
    {
        /// <summary>
        /// get user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns>user</returns>
        public async Task<User> GetUserByEmailAsync(string email)
        {
            var user = new User()
            {
                Id = 1,
                FirstName = "Oleksiy",
                LastName = "Levenets",
                Email = email,
                Disabled = false,
                CreatedDate = DateTime.Now,
                ModifiedDate = DateTime.Now,
                Password = "P@ssword123"
            };

            return await Task.FromResult(user);
        }

        /// <summary>
        /// get user roles
        /// </summary>
        /// <param name="userId"></param>
        /// <returns>list of user roles</returns>
        public async Task<IEnumerable<string>> GetUserRolesAsync(int userId)
        {
            var roles = new List<string>();
            roles.Add("Administrator");

            return await Task.FromResult(roles);
        }

        /// <summary>
        /// get user by refresh token
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<User> GetUserByRefreshTokenAsync(string refreshToken)
        {
            var user = new User()
            {
                Id = 1,
                FirstName = "Oleksiy",
                LastName = "Levenets",
                Email = "email@gmail.com",
                Disabled = false,
                CreatedDate = DateTime.Now,
                ModifiedDate = DateTime.Now,
                Password = "P@ssword123",
                RefreshTokens = new List<RefreshToken>()
                {
                    new RefreshToken()
                    {
                        Id = 1,
                        Token = refreshToken,
                        Expires = DateTime.UtcNow.AddDays(7),
                        CreatedByIp = "",
                        UserId = 1
                    }
                }
            };

            return await Task.FromResult(user);
        }

        /// <summary>
        /// save refresh token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<bool> SaveRefreshToken(int userId, RefreshToken refreshToken)
        {
            return await Task.FromResult(true);
        }

        /// <summary>
        /// delete refresh token
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<bool> DeleteRefreshToken(RefreshToken refreshToken)
        {
            return await Task.FromResult(true);
        }

    }
}

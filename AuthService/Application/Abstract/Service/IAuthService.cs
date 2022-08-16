using AuthService.Application.Common;
using AuthService.Application.Common.DTOs;

namespace AuthService.Application.Abstract.Service
{
    public interface IAuthService
    {
        Task<IResponse> LoginAsync(LoginRequest loginRequest);
        
        Task<IResponse> RefreshTokenAsync(RefreshTokenRequest request);
    }
}

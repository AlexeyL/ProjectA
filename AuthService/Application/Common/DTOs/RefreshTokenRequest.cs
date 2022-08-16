using FluentValidation;

namespace AuthService.Application.Common.DTOs
{
    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
        public string RemoteIpAddress { get; set; } = string.Empty;

        public RefreshTokenRequest(string refreshToken, string remoteIpAddress)
        {
            RefreshToken = refreshToken;
            RemoteIpAddress = remoteIpAddress;
        }
    }

    public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
    {
        public RefreshTokenRequestValidator()
        {
            RuleFor(x => x.RefreshToken).NotEmpty().WithMessage("Refresh token is required");
            RuleFor(x => x.RemoteIpAddress).NotEmpty().WithMessage("IP address is required");
        }
    }
}

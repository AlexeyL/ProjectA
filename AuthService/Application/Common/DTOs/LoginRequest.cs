using FluentValidation;

namespace AuthService.Application.Common.DTOs
{
    public class LoginRequest
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string RemoteIpAddress { get; set; } = string.Empty;
    }

    public class LoginRequestValidator: AbstractValidator<LoginRequest>
    {
        public LoginRequestValidator()
        {
            RuleFor(x => x.UserName).EmailAddress().NotEmpty().WithMessage("Please specify an Email");
            RuleFor(x => x.Password).NotEmpty().WithMessage("Please speciry a Password");
            RuleFor(x => x.Password).Length(6, 50).WithMessage("Password must contain at least 6 symbols");
            RuleFor(x => x.RemoteIpAddress).NotEmpty().WithMessage("IP address is required");
        }
    }
}

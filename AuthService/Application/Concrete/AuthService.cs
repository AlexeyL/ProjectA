using AuthService.Application.Abstract.DataService;
using AuthService.Application.Abstract.Service;
using AuthService.Application.Common;
using AuthService.Application.Common.DTOs;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Application.Concrete
{
    public class AuthService : IAuthService
    {
        private readonly JwtIssuerOptions _jwtOptions;
        private readonly IValidator<LoginRequest> _loginRequestValidator;
        private readonly IValidator<RefreshTokenRequest> _refreshTokenRequestValidator;
        private readonly IUserDataService _userDataService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(IOptionsMonitor<JwtIssuerOptions> jwtOptions,
            IValidator<LoginRequest> loginRequestValidator,
            IValidator<RefreshTokenRequest> refreshTokenRequestValidator,
            IUserDataService userDataService,
            ILogger<AuthService> logger)
        {
            _jwtOptions = jwtOptions.CurrentValue;

            ThrowIfInvalidOptions(_jwtOptions);

            _loginRequestValidator = loginRequestValidator;
            _refreshTokenRequestValidator = refreshTokenRequestValidator;
            _userDataService = userDataService;
            _logger = logger;
        }

        /// <summary>
        /// login user
        /// </summary>
        /// <param name="loginRequest"></param>
        /// <returns>access token, refresh token or validation result</returns>
        public async Task<IResponse> LoginAsync(LoginRequest loginRequest)
        {
            var validationResult = await _loginRequestValidator.ValidateAsync(loginRequest);

            if (!validationResult.IsValid)
            {
                return new Response(false, validationResult);
            }

            var user = await _userDataService.GetUserByEmailAsync(loginRequest.UserName);

            if (user == null)
            {
                return new Response(true, validationResult, null);
            }

            if (!ValidatePassword(user, loginRequest.Password))
            {
                return new Response(true, validationResult, null);
            }

            var userRoles = await _userDataService.GetUserRolesAsync(user.Id);
            var claims = await GenerateClaimsList(user.Email, user.Id.ToString(), userRoles);
            var accessToken = GenerateAcessTokenAsync(claims);
            var refreshToken = GenerateRefreshToken(user.Id, loginRequest.RemoteIpAddress);

            var isRefreshTokenSaved = await _userDataService.SaveRefreshToken(user.Id, refreshToken);

            if (isRefreshTokenSaved)
            {
                var args = new object[] { loginRequest, refreshToken, user };
                _logger.LogCritical("LoginAsync: Refresh token has not been saved", args);
            }

            var loginResponse = new AuthResponse(user.Id, user.Email, accessToken, refreshToken.Token);

            return new Response(true, validationResult, loginResponse);
        }

        /// <summary>
        /// refresh token
        /// </summary>
        /// <param name="refreshTokenRequest"></param>
        /// <returns>access token, refresh token or validation result</returns>
        public async Task<IResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest)
        {
            var validationResult = await _refreshTokenRequestValidator.ValidateAsync(refreshTokenRequest);

            if (!validationResult.IsValid)
            {
                return new Response(false, validationResult);
            }

            var user = await _userDataService.GetUserByRefreshTokenAsync(refreshTokenRequest.RefreshToken);
            
            if (user == null)
            {
                return new Response(true, validationResult, null);
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == refreshTokenRequest.RefreshToken);

            if (refreshToken == null || refreshToken.IsExpired)
            {
                return new Response(true, validationResult, null);
            }

            var isRefreshTokenDeleted = await _userDataService.DeleteRefreshToken(refreshToken);

            if (!isRefreshTokenDeleted)
            {
                var args = new object[] { refreshTokenRequest, user };
                _logger.LogCritical("RefreshTokenAsync: Refresh token has not been deleted", args);
            }

            var userRoles = await _userDataService.GetUserRolesAsync(user.Id);
            var claims = await GenerateClaimsList(user.Email, user.Id.ToString(), userRoles);
            var accessToken = GenerateAcessTokenAsync(claims);
            var newRefreshToken = GenerateRefreshToken(user.Id, refreshTokenRequest.RemoteIpAddress);

            var isRefreshTokenSaved = await _userDataService.SaveRefreshToken(user.Id, newRefreshToken);

            if (isRefreshTokenSaved)
            {
                var args = new object[] { newRefreshToken, user };
                _logger.LogCritical("RefreshTokenAsync: Refresh token has not been saved", args);
            }

            var refreshTokenResponse = new AuthResponse(user.Id, user.Email, accessToken, refreshToken.Token);

            return new Response(true, validationResult, refreshTokenResponse);
        }


        #region === Private Methods ===


        /// <summary>
        /// validate user password
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns>is valid</returns>
        private bool ValidatePassword(User user, string password)
        {
            return true;
        }

        /// <summary>
        /// generate list of claims
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="id"></param>
        /// <param name="roles"></param>
        /// <returns></returns>
        private async Task<List<Claim>> GenerateClaimsList(string userName, string id, IEnumerable<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId, id),
                new Claim(JwtRegisteredClaimNames.Name, userName),
                new Claim(JwtRegisteredClaimNames.Email, userName),
                new Claim(JwtRegisteredClaimNames.Sub, userName),
                new Claim(JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }

        /// <summary>
        /// generate token
        /// </summary>
        /// <param name="claims"></param>
        /// <returns>token</returns>
        private string GenerateAcessTokenAsync(List<Claim> claims)
        {
            // Create the JWT security token and encode it.
            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                notBefore: _jwtOptions.NotBefore,
                expires: _jwtOptions.Expiration,
                signingCredentials: _jwtOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return encodedJwt;
        }

        /// <summary>
        /// generate refresh token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="remoteIpAddress"></param>
        /// <returns>refresh token</returns>
        private RefreshToken GenerateRefreshToken(int userId, string remoteIpAddress)
        {
            var refreshToken = new RefreshToken();
            refreshToken.UserId = userId;
            refreshToken.CreatedByIp = remoteIpAddress;
            refreshToken.Expires = DateTime.UtcNow.Add(TimeSpan.FromDays(7));

            var userIdHashString = string.Empty;
            var userIpAddressHashString = string.Empty;

            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] userIdBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(userId.ToString()));
                userIdHashString = Convert.ToBase64String(userIdBytes);

                byte[] userIpAddressBytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(remoteIpAddress));
                userIpAddressHashString = Convert.ToBase64String(userIpAddressBytes);
            }

            var randomNumber = new byte[32];
            var randomNumberString = string.Empty;
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                randomNumberString = Convert.ToBase64String(randomNumber);
            }

            var tokenString = $"{userIdHashString}{userIpAddressHashString}{randomNumberString}";
            refreshToken.Token = tokenString;

            return refreshToken;
        }

        /// <summary>
        /// validates JwtIssuerOptions and throws an exception if invalid
        /// </summary>
        /// <param name="options"></param>
        private static void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
            }
        }

        /// <returns>date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        private static long ToUnixEpochDate(DateTime date)
          => (long)Math.Round((date.ToUniversalTime() -
                               new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                              .TotalSeconds);
        #endregion
    }
}

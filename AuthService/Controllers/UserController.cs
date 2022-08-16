using AuthService.Application.Abstract.Service;
using AuthService.Application.Common.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;

        public UserController(IAuthService authService)
        {
            _authService = authService;
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            var remoteIpAddress = GetIpAddress();
            loginRequest.RemoteIpAddress = remoteIpAddress;

            var response = await _authService.LoginAsync(loginRequest);

            if (!response.Success)
            {
                return BadRequest(response);
            }

            if (response.Success && response.Result == null)
            {
                return Unauthorized();
            }

            var loginResponse = (AuthResponse)response.Result;

            SetTokenCookie(loginResponse.RefreshToken);

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var remoteIpAddress = GetIpAddress();

            var refreshTokenRequest = new RefreshTokenRequest(refreshToken, remoteIpAddress);

            var response = await _authService.RefreshTokenAsync(refreshTokenRequest);

            if (!response.Success)
            {
                return BadRequest(response);
            }

            if (response.Success && response.Result == null)
            {
                return Unauthorized();
            }

            var refreshTokenResponse = (AuthResponse)response.Result;

            SetTokenCookie(refreshTokenResponse.RefreshToken);

            return Ok(response);
        }

        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetUserById(int id)
        {
            return Ok("hello world" + id);
        }

        #region === private methods ===


        /// <summary>
        /// set refresh token cookie
        /// </summary>
        /// <param name="token"></param>
        private void SetTokenCookie(string token)
        {
            // append cookie with refresh token to the http response
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };

            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        /// <summary>
        /// get user ip address
        /// </summary>
        /// <returns>ip address</returns>
        private string GetIpAddress()
        {
            // get source ip address for the current request
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }


        #endregion
    }
}

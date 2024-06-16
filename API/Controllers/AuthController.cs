using Core.Helpers;
using Core.ResultObjects;
using Core.Security;
using Core.Security.Abstract;
using Core.Security.Requests;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class AuthController : CustomControllerBase
{
    private readonly IAuthenticationService _authenticationService;

    public AuthController(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    [HttpPost]
    public async Task<IActionResult> CreateToken(LoginRequest loginDto, bool? isHttpOnly, string? refreshToken)
    {
        if (refreshToken != null)
        {
            var tokenResult = await _authenticationService.CreateTokenByRefreshTokenAsync(refreshToken);
            if (tokenResult.IsSuccessed)
            {
                return CreateResult(tokenResult);
            }
        }
        refreshToken = HttpContext.Request.Cookies["RefreshToken"];
        if (refreshToken != null)
        {
            var tokenResult = await _authenticationService.CreateTokenByRefreshTokenAsync(refreshToken);
            if (tokenResult.IsSuccessed)
            {
                Response.Cookies.Append("RefreshToken",
                tokenResult.Data.RefreshToken,
                new CookieOptions
                {
                    Expires = tokenResult.Data.RefreshTokenExpiration,
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None
                }
                );
                Response.Cookies.Append("AccessToken",
                tokenResult.Data.AccessToken,
                new CookieOptions
                {
                    Expires = tokenResult.Data.AccessTokenExpiration,
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None
                }
                );
                return StatusCode(200);
            }
        }
        if (isHttpOnly == true)
        {
            var tokenResult = await _authenticationService.CreateTokenAsync(loginDto);
            if (!tokenResult.IsSuccessed)
            {
                return CreateResult(tokenResult);
            }
            Response.Cookies.Append("RefreshToken",
            tokenResult.Data.RefreshToken,
            new CookieOptions
            {
                Expires = tokenResult.Data.RefreshTokenExpiration,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            }
            );
            Response.Cookies.Append("AccessToken",
            tokenResult.Data.AccessToken,
            new CookieOptions
            {
                Expires = tokenResult.Data.AccessTokenExpiration,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            }
            );
            return StatusCode(200);
        }
        return CreateResult(await _authenticationService.CreateTokenAsync(loginDto));
    }
    [HttpPost]
    public async Task<IActionResult> CreateTokenByRefreshToken(string? refreshToken)
    {
        if (refreshToken == null)
        {
            refreshToken = HttpContext.Request.Cookies["RefreshToken"];
            if (refreshToken == null)
            {
                return Unauthorized();
            }
            var tokenResult = await _authenticationService.CreateTokenByRefreshTokenAsync(refreshToken);
            if (!tokenResult.IsSuccessed)
            {
                return CreateResult(tokenResult);
            }
            Response.Cookies.Append("RefreshToken",
            tokenResult.Data.RefreshToken,
            new CookieOptions
            {
                Expires = tokenResult.Data.RefreshTokenExpiration,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            }
            );
            Response.Cookies.Append("AccessToken",
            tokenResult.Data.AccessToken,
            new CookieOptions
            {
                Expires = tokenResult.Data.AccessTokenExpiration,
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            }
            );
            return StatusCode(200);
        }
        return CreateResult(await _authenticationService.CreateTokenByRefreshTokenAsync(refreshToken));
    }
    [HttpPost]
    public async Task<IActionResult> RevokeRefreshToken(string? refreshToken)
    {
        Result<NoContent> revokeResult;
        if (refreshToken == null)
        {
            refreshToken = HttpContext.Request.Cookies["RefreshToken"];
            if (refreshToken == null)
            {
                return Unauthorized();
            }
            revokeResult = await _authenticationService.RevokeRefreshToken(refreshToken);
            if (!revokeResult.IsSuccessed)
            {
                return CreateResult(revokeResult);
            }
            Response.Cookies.Delete("AccessToken");
            Response.Cookies.Delete("RefreshToken");
            return CreateResult(revokeResult);
        }
        revokeResult = await _authenticationService.RevokeRefreshToken(refreshToken);
        return CreateResult(revokeResult);
    }
    //[HttpPost]
    //public string GetRefreshFromCookie(string? refreshToken)
    //{
    //    refreshToken = HttpContext.Request.Cookies["RefreshToken"];
    //    return refreshToken;
    //}
}

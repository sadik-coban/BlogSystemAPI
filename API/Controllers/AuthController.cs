using Core.Helpers;
using Core.ResultObjects;
using Core.Security.Abstract;
using Core.Security.Concrete;
using Core.Security.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class AuthController : CustomControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;
    public AuthController(IAuthenticationService authenticationService, ITokenService tokenService, IUserService userService)
    {
        _authenticationService = authenticationService;
        _tokenService = tokenService;
        _userService = userService;
    }

    [HttpPost]
    public async Task<IActionResult> CreateToken(LoginRequest loginDto, bool? isHttpOnly, string? refreshToken)
    {
        if (refreshToken != null)
        {
            var signInResult = await _authenticationService.CheckPasswordSignInAsync(loginDto);
            if(!signInResult.Succeeded)
            {
                return Unauthorized();
            }
            var tokenResult = await _authenticationService.CreateTokenByRefreshTokenAsync(refreshToken);
            if (tokenResult.IsSuccessed)
            {
                if(isHttpOnly == true)
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
                return CreateResult(tokenResult);
            }
        }
        refreshToken = HttpContext.Request.Cookies["RefreshToken"];
        if (refreshToken != null)
        {
            var signInResult = await _authenticationService.CheckPasswordSignInAsync(loginDto);
            if (!signInResult.Succeeded)
            {
                return Unauthorized();
            }
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
            revokeResult = await _authenticationService.RevokeRefreshTokenAsync(refreshToken);
            if (!revokeResult.IsSuccessed)
            {
                return CreateResult(revokeResult);
            }
            Response.Cookies.Delete("AccessToken");
            Response.Cookies.Delete("RefreshToken");
            return CreateResult(revokeResult);
        }
        revokeResult = await _authenticationService.RevokeRefreshTokenAsync(refreshToken);
        return CreateResult(revokeResult);
    }

    [HttpPost]
    public async Task<IActionResult> RevokeAllRefreshToken(string? refreshToken)
    {
        Result<NoContent> revokeResult;
        if (refreshToken == null)
        {
            refreshToken = HttpContext.Request.Cookies["RefreshToken"];
            if (refreshToken == null)
            {
                return Unauthorized();
            }
            revokeResult = await _authenticationService.RevokeAllRefreshTokensAsync(UserId!.Value, refreshToken);
            if (!revokeResult.IsSuccessed)
            {
                return CreateResult(revokeResult);
            }
            Response.Cookies.Delete("AccessToken");
            Response.Cookies.Delete("RefreshToken");
            return CreateResult(revokeResult);
        }
        revokeResult = await _authenticationService.RevokeAllRefreshTokensAsync(UserId!.Value, refreshToken);
        return CreateResult(revokeResult);
    }

    [HttpPost]
    [Authorize]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest model)
    {
        return CreateResult(await _authenticationService.ChangePasswordAsync(model,User));
    }

    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(Guid id,string token)
    {
        return CreateResult(await _authenticationService.ConfirmEmailAsync(id, token)); //Redirect React page Url if success
    }

    [HttpGet]
    public async Task<IActionResult> SendPasswordResetLink(string username)
    {
        var user = await _userService.FindByNameAsync(username);
        var token = await _tokenService.GeneratePasswordResetTokenAsync(user);
        var url = Url.Action(nameof(ResetPassword), "Auth", new { id = user.Id, token }, Request.Scheme); //Create React Page and put page url to this Url
        await _authenticationService.SendPasswordResetLinkAsync(user, url);
        return Ok(token);                        //test purpose!
    }

    [HttpPost]
    public async Task<IActionResult> ResetPassword(CreateNewPasswordRequest model)
    {
        await _authenticationService.ResetPasswordAsync(model);
        return Ok();            
    }

    [HttpPost]
    [Authorize]
    public async Task<IActionResult> SendEmailChangeLink(string email)
    {
        var user = await _userService.FindByIdAsync(UserId!.Value);
        var token = await _tokenService.GenerateEmailChangeTokenAsync(user, email);
        var url = Url.Action(nameof(ChangeEmailAndUserName), "Auth", new { id = user.Id, token, email = email }, Request.Scheme);
        await _authenticationService.SendEmailChangeLinkAsync(user, email, url);
        return Ok();
    }

    [HttpGet]
    public async Task<IActionResult> ChangeEmailAndUserName(Guid id, string email, string token)
    {
        await _authenticationService.ChangeEmailAndUserNameAsync(id, email, token);
        return Ok();
    }

    //public async Task<IActionResult> RevokeAllRefreshToken(string? refreshToken)
    //{
    //    return CreateResult(await _authenticationService.RevokeAllRefreshTokensAsync(UserId!.Value, refreshToken));
    //}
}

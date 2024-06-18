using Core.External.Abstract;
using Core.Helpers;
using Core.Identity;
using Core.Security.Abstract;
using Core.Security.Concrete;
using Core.Security.Requests;
using Core.Security.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NETCore.MailKit.Core;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class UserController : CustomControllerBase
{
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;
    private readonly IEmailSender<ApplicationUser> _emailService;
    public UserController(IUserService userService, ITokenService tokenService, IEmailSender<ApplicationUser> emailService)
    {
        _userService = userService;
        _tokenService = tokenService;
        _emailService = emailService;
    }

    [HttpPost]
    public async Task<IActionResult> CreateUser(RegisterRequest addAppUserDto)
    {
        var result = await _userService.CreateUserAsync(addAppUserDto);
        if (result.IsSuccessed)
        {
            var user = result.Data;
            var token = await _tokenService.GenerateEmailConfirmationTokenAsync(user);
            var url = Url.Action("ConfirmEmail", "Auth", new { id = user.Id, token }, Request.Scheme);
            await _emailService.SendConfirmationLinkAsync(user, user.Email, url);
            return Ok(new RegisterResponse
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email
            });
        }
        return CreateResult(result);
    }

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> GetUserFromClaim()
    {
        var email = HttpContext.User.Claims.Single(x => x.Type == ClaimTypes.Email).Value;
        return CreateResult(await _userService.GetUserByNameAsync(email));
    }
}

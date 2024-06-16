using Core.Helpers;
using Core.Security.Abstract;
using Core.Security.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class UserController : CustomControllerBase
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpPost]
    public async Task<IActionResult> CreateUser(RegisterRequest addAppUserDto)
    {
        return CreateResult(await _userService.CreateUserAsync(addAppUserDto));
    }

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> GetUserFromClaim()
    {
        var email = HttpContext.User.Claims.Single(x => x.Type == ClaimTypes.Email).Value;
        return CreateResult(await _userService.GetUserByNameAsync(email));
    }
}

using Core.Identity;
using Core.ResultObjects;
using Core.Security.Abstract;
using Core.Security.Mapping;
using Core.Security.Requests;
using Core.Security.Responses;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Core.Security.Concrete;
public class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ITokenService _tokenService;
    public UserService(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, ITokenService tokenService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _tokenService = tokenService;
    }

    public async Task<Result<ApplicationUser>> CreateUserAsync(RegisterRequest registerRequest)
    {
        var user = CustomMapper.Mapper.Map<ApplicationUser>(registerRequest);
        user.UserName = registerRequest.Email;
        var result = await _userManager.CreateAsync(user, registerRequest.Password);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(x => x.Description).ToList();
            return Result<ApplicationUser>.Fail(errors, 400);
        }

        return Result<ApplicationUser>.Success(user, 201);

    }

    public async Task<Result<UserResponse>> GetUserByNameAsync(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return Result<UserResponse>.Fail("Not found", 404);
        }
        return Result<UserResponse>.Success(CustomMapper.Mapper.Map<UserResponse>(user), 200);
    }
    public async Task<ApplicationUser> FindByNameAsync(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        return user;
    }

    public Task<ApplicationUser> FindByIdAsync(Guid id)
    {
        var user = _userManager.FindByIdAsync(id.ToString());
        return user;
    }
}
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

    public UserService(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task<Result<RegisterResponse>> CreateUserAsync(RegisterRequest registerRequest)
    {
        var user = CustomMapper.Mapper.Map<ApplicationUser>(registerRequest);
        user.UserName = registerRequest.Email;
        var result = await _userManager.CreateAsync(user, registerRequest.Password);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(x => x.Description).ToList();
            return Result<RegisterResponse>.Fail(errors, 400);
        }
        return Result<RegisterResponse>.Success(CustomMapper.Mapper.Map<RegisterResponse>(user), 201);

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
}
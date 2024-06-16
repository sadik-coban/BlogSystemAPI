using Core.ResultObjects;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Core.Helpers;
public class CustomControllerBase : ControllerBase
{
    protected Guid? UserId => User.Identity?.IsAuthenticated == true ? Guid.Parse(User.Claims.Single(x => x.Type == ClaimTypes.NameIdentifier).Value) : default;
    public static IActionResult CreateResult<T>(Result<T> result)
    {
        return new ObjectResult(result)
        {
            StatusCode = result.StatusCode
        };
    }
}

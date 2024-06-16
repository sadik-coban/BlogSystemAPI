using Core.ResultObjects;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Helpers;
public class CustomControllerBase : ControllerBase
{
    public static IActionResult CreateResult<T>(Result<T> result)
    {
        return new ObjectResult(result)
        {
            StatusCode = result.StatusCode
        };
    }
}

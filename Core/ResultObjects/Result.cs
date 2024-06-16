using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Core.ResultObjects;
//Factory Design Pattern
public class Result<T>
{
    public T? Data { get; set; }
    public List<string>? Errors { get; set; }

    [JsonIgnore]
    public int StatusCode { get; set; }

    [JsonIgnore]
    public bool IsSuccessed { get; set; }

    public static Result<T> Success(T data, int statusCode)
    {
        return new Result<T>
        {
            Data = data,
            StatusCode = statusCode,
            IsSuccessed = true
        };
    }

    public static Result<T> Success(int statusCode)
    {
        return new Result<T>
        {
            Data = default(T),
            StatusCode = statusCode,
            IsSuccessed = true

        };
    }

    public static Result<T> Fail(List<string> errors, int statusCode)
    {
        return new Result<T>
        {
            Errors = errors,
            StatusCode = statusCode,
            IsSuccessed = false
        };
    }

    public static Result<T> Fail(string error, int statusCode)
    {
        return new Result<T>
        {
            Errors = new List<string> { error },
            StatusCode = statusCode,
            IsSuccessed = false
        };
    }
}
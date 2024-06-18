using Core;
using Core.Data;
using Core.Extensions;
using Core.External.Options;
using Core.Identity;
using Core.Security.Abstract;
using Core.Security.Concrete;
using Core.Security.Options;
using Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SqlServerConnection"));
});

builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
    options.User.RequireUniqueEmail = true;
    options.Password.RequireDigit = builder.Configuration.GetValue<bool>("Security:Password:RequireDigit");
    options.Password.RequiredLength = builder.Configuration.GetValue<int>("Security:Password:RequiredLength");
    options.Password.RequiredUniqueChars = builder.Configuration.GetValue<int>("Security:Password:RequiredUniqueChars");
    options.Password.RequireLowercase = builder.Configuration.GetValue<bool>("Security:Password:RequireLowercase");
    options.Password.RequireUppercase = builder.Configuration.GetValue<bool>("Security:Password:RequireUppercase");
    options.Password.RequireNonAlphanumeric = builder.Configuration.GetValue<bool>("Security:Password:RequireNonAlphanumeric");

    options.Lockout.MaxFailedAccessAttempts = builder.Configuration.GetValue<int>("Security:Lockout:MaxFailedAccessAttempts");
    options.Lockout.DefaultLockoutTimeSpan = builder.Configuration.GetValue<TimeSpan>("Security:Lockout:DefaultLockoutTimeSpan");
}).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.Configure<CustomTokenOptions>(builder.Configuration.GetSection("TokenOptions"));
var emailSettings = builder.Configuration.GetSection(EmailOptions.Email).Get<EmailOptions>();
var tokenOptions = builder.Configuration.GetSection("TokenOptions").Get<CustomTokenOptions>();

builder.Services.AddCoreServices(builder.Configuration, emailSettings);
builder.Services.AddAuthentication(tokenOptions);

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();

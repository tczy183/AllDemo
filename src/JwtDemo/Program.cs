using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "My API", Version = "v1" });
    // Add a security definition to the Swagger document,
    options.AddSecurityDefinition("JwtBearer", new OpenApiSecurityScheme
    {
        Description = "直接输入Token即可",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });
    // Add a security requirement to each operation in the Swagger document,
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "JwtBearer"
                }
            },
            Array.Empty<string>()
        }
    });
});
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidAudience = "http://localhost:5602",
        ValidIssuer = "http://localhost:5602",
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("kb5AuKOVm3ghviJNjOWtCYdPyE3KzZ/td78HAAFB4Vo="))
    };
});
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/hello", () => "Hello World!")
    .WithName("HelloWorld")
    .RequireAuthorization()
    .WithOpenApi();

app.MapPost("/login", ([FromBody] LoginRequest loginRequest) =>
{
    if (loginRequest is { Username: "admin", Password: "admin" })
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, loginRequest.Username),
            new Claim(ClaimTypes.Role, "Admin"),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("kb5AuKOVm3ghviJNjOWtCYdPyE3KzZ/td78HAAFB4Vo="));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "http://localhost:5602",
            audience: "http://localhost:5602",
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    return "Invalid username or password";
});

app.MapGet("Hs256", (string data, string key) =>
{
    var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
    var hashValue = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    return Convert.ToBase64String(hashValue);
});
app.Run();

public record LoginRequest(string Username, string Password);
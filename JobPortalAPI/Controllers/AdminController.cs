using Microsoft.AspNetCore.Mvc;
using JobPortalAPI.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JobPortalAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private const string AdminEmail = "admin@gmail.com";
        private const string AdminPassword = "admin";
        private readonly IConfiguration _configuration;

        public AdminController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //http post login method 

        [HttpPost("admin-login")]
        public IActionResult AdminLogin([FromBody] AdminLoginModel admin)
        {
            if (admin == null)
                return BadRequest(new { message = "Invalid login data." });

            if (admin.Email == AdminEmail && admin.Password == AdminPassword)
            {
                var token = GenerateJwtToken(admin.Email);

                return Ok(new
                {
                    token,
                    message = "Admin login successful!"
                });
            }
            else
            {
                return Unauthorized(new { message = "Unauthorized: Invalid admin credentials." });
            }
        }


        // token generated after login 

        private string GenerateJwtToken(string email)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Email, email),
                new Claim("Role", "Admin"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpireMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

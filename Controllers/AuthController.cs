using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using eventosApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using System.Net.Sockets;
using System.Net;
using eventosApi.Services;



namespace eventosApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IConfiguration _config;
        private readonly IMailService _mailService;

        public AuthController(DataContext context, IConfiguration config, IMailService mailService)
        {
            _context = context;
            _config = config;
            _mailService = mailService;
        }

        // POST: api/user/register ------------------------------------------------------------------------
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromForm] User user)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            if (existingUser != null)
                return BadRequest("Ya existe un usuario con ese correo.");

            string hashedPassword = Convert.ToBase64String(
                KeyDerivation.Pbkdf2(
                    password: user.PasswordHash,
                    salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                )
            );

            var newUser = new User
            {
                Username = user.Username,
                Email = user.Email,
                PasswordHash = hashedPassword,
                Role = Role.Usuario
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            return Ok("¡Usuario registrado exitosamente!");
        }

        // POST: api/user/login --------------------------------------------------------------------------
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromForm] LoginModel loginModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == loginModel.Email);
            if (user == null)
                return BadRequest("Credenciales inválidas.");

            string hashed = Convert.ToBase64String(
                KeyDerivation.Pbkdf2(
                    password: loginModel.Password,
                    salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                )
            );

            if (user.PasswordHash != hashed)
                return BadRequest("Credenciales inválidas.");

            // Crear token
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_config["TokenAuthentication:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email),
                new Claim("Username", user.Username),
                new Claim(ClaimTypes.Role, user.Role.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["TokenAuthentication:Issuer"],
                audience: _config["TokenAuthentication:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
        }

        // POST: api/Auth/forgot-password
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromForm] string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return BadRequest("La dirección de correo electrónico no puede estar vacía.");
            }

            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == email);
            if (user == null)
            {
                return NotFound("No se encontró ningún usuario con esta dirección de correo electrónico.");
            }

            //contraseña aleatoria
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var nuevaClave = new string(Enumerable.Repeat(chars, 8)
                .Select(s => s[new Random().Next(s.Length)]).ToArray());

            // Hashea y actualiza la contraseña en la bd
            string hashedPassword = Convert.ToBase64String(
                KeyDerivation.Pbkdf2(
                    password: nuevaClave,
                    salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                )
            );

            user.PasswordHash = hashedPassword;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            var displayName = string.IsNullOrEmpty(user.Username) ? user.Email : user.Username;
            var subject = "Nueva Contraseña para Eventos ULP";
            var body = $@"
                <!DOCTYPE html>
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Restablecimiento de Contraseña</h2>
                    <p>Hola {displayName},</p>
                    <p>Has solicitado restablecer tu contraseña. Tu nueva contraseña temporal es:</p>
                    <h3 style='color: #007bff; font-weight: bold;'>{nuevaClave}</h3>
                    <p>Te recomendamos que cambies esta contraseña después de iniciar sesión.</p>
                    <br>
                    <p>Saludos,</p>
                    <p>El equipo de Eventos ULP</p>
                </body>
                </html>";

            await _mailService.SendEmailAsync(user.Email, subject, body);

            return Ok("Se ha generado una nueva contraseña y se ha enviado a tu correo electrónico.");
        }

        // POST: api/Auth/reset-password
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromForm] string token, [FromForm] string newPassword)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["TokenAuthentication:SecretKey"]);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true
            };

            SecurityToken validatedToken;
            ClaimsPrincipal principal;
            try
            {
                principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);
            }
            catch
            {
                return BadRequest("El enlace de recuperación es inválido o ha expirado.");
            }

            var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return BadRequest("Token inválido.");
            }

            int userId = int.Parse(userIdClaim.Value);
            var user = await _context.Users.FindAsync(userId);

            if (user == null)
            {
                return BadRequest("Usuario no encontrado.");
            }

            string hashedPassword = Convert.ToBase64String(
                KeyDerivation.Pbkdf2(
                    password: newPassword,
                    salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                )
            );

            user.PasswordHash = hashedPassword;
            await _context.SaveChangesAsync();

            return Ok("Contraseña restablecida exitosamente.");
        }

    
    }
}
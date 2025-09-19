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


namespace eventosApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IConfiguration _config;

        public AuthController(DataContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
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


        //ENVIAR MAIL PARA RECUPERAR CONTRASEÑA




        // POST: api/auth/email (Enviar email para recuperar contraseña)
        [HttpPost("email")]
        [AllowAnonymous]
        public async Task<IActionResult> EnviarEmail([FromForm] string email)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(email))
                {
                    return BadRequest("La dirección de correo electrónico no puede estar vacía.");
                }

                var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == email);
                if (user == null)
                {
                    // Devolver un mensaje genérico para no exponer si el email existe
                    return NotFound("No se encontró ningún usuario con esta dirección de correo electrónico.");
                }

                // Se utiliza el Username del usuario o su email como fallback para el nombre.
                var displayName = string.IsNullOrEmpty(user.Username) ? user.Email : user.Username;

                var key = new SymmetricSecurityKey(
                    Encoding.ASCII.GetBytes(_config["TokenAuthentication:SecretKey"])
                );
                var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email),
            };

                var token = new JwtSecurityToken(
                    issuer: _config["TokenAuthentication:Issuer"],
                    audience: _config["TokenAuthentication:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(5), // Token expira en 5 minutos
                    signingCredentials: credenciales
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                var ipAddress = GetLocalIpAddress();

                // Usar el esquema del request (http o https)
                var resetLink = $"{Request.Scheme}://{ipAddress}:{Request.Host.Port}/api/Auth/generarPassword?access_token={tokenString}";

                var message = new MimeMessage();
                message.To.Add(new MailboxAddress(displayName, user.Email));
                message.From.Add(new MailboxAddress("Eventos API", _config["SMTP:From"]));
                message.Subject = "Restablecimiento de Contraseña";
                message.Body = new TextPart("html") { Text = mail1(displayName, resetLink) };

                using var client = new SmtpClient();
                client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                await client.ConnectAsync(_config["SMTP:Host"], int.Parse(_config["SMTP:Port"]), MailKit.Security.SecureSocketOptions.Auto);
                await client.AuthenticateAsync(_config["SMTP:User"], _config["SMTP:Pass"]);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);

                return Ok("Se ha enviado el enlace de restablecimiento de contraseña correctamente.");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        private string GetLocalIpAddress()
        {
            string localIp = null;
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    localIp = ip.ToString();
                    break;
                }
            }
            return localIp;
        }

        // GET: api/auth/generarPassword
        [HttpGet("generarPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> GenerarPassword(string access_token)
        {
            try
            {
                if (string.IsNullOrEmpty(access_token))
                {
                    return BadRequest("Token de restablecimiento no proporcionado.");
                }

                // Validar el token y verificar su firma, emisor, audiencia y expiración.
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_config["TokenAuthentication:SecretKey"]);
                tokenHandler.ValidateToken(
                    access_token,
                    new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = true,
                        ValidIssuer = _config["TokenAuthentication:Issuer"],
                        ValidateAudience = true,
                        ValidAudience = _config["TokenAuthentication:Audience"],
                        ClockSkew = TimeSpan.Zero
                    },
                    out SecurityToken validatedToken
                );

                // Obtener el email del usuario del token JWT
                var jwtToken = (JwtSecurityToken)validatedToken;
                var userEmail = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

                if (string.IsNullOrEmpty(userEmail))
                {
                    return BadRequest("El token no contiene la información del usuario.");
                }

                // Buscar al usuario en la base de datos usando el email del token
                var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == userEmail);

                if (user == null)
                {
                    return BadRequest("No se encontró ningún usuario asociado a este token.");
                }
                else
                {
                    // Generar una nueva contraseña aleatoria de 8 caracteres
                    Random rand = new Random();
                    const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                    var nuevaClave = new string(
                        Enumerable.Repeat(chars, 8).Select(s => s[rand.Next(s.Length)]).ToArray()
                    );

                    // Hashear y actualizar la nueva contraseña en la base de datos
                    await HashAndUpdatePassword(nuevaClave, user);

                    // Usar el Username del usuario o su email como fallback para el nombre.
                    var displayName = string.IsNullOrEmpty(user.Username) ? user.Email : user.Username;

                    // Crear y enviar el correo electrónico con la nueva contraseña
                    var message = new MimeMessage();
                    message.To.Add(new MailboxAddress(displayName, user.Email));
                    message.From.Add(new MailboxAddress("Eventos API", _config["SMTP:From"]));
                    message.Subject = "Nueva Contraseña";
                    message.Body = new TextPart("html")
                    {
                        Text = mail2(displayName, nuevaClave)
                    };

                    using (var client = new SmtpClient())
                    {
                        client.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
                        await client.ConnectAsync(_config["SMTP:Host"], int.Parse(_config["SMTP:Port"]), MailKit.Security.SecureSocketOptions.Auto);
                        await client.AuthenticateAsync(_config["SMTP:User"], _config["SMTP:Pass"]);
                        await client.SendAsync(message);
                        await client.DisconnectAsync(true);
                    }

                    return Ok("Se ha restablecido la contraseña correctamente.");
                }
            }
            catch (SecurityTokenValidationException)
            {
                // Este error se lanza si el token ha expirado, está mal firmado, etc.
                return StatusCode(401, "Token de restablecimiento no válido o ha expirado.");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        private async Task HashAndUpdatePassword(string newPassword, User user)
        {
            // Generar el hash de la nueva contraseña
            string hashedPassword = Convert.ToBase64String(
                KeyDerivation.Pbkdf2(
                    password: newPassword,
                    salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                )
            );

            // Almacenar el hash de la contraseña en la base de datos
            user.PasswordHash = hashedPassword;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
        }

        private String mail1(String nombre, String link)
        {
            return $@"
                <!DOCTYPE html>
                <html lang='es'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>Restablecer Contraseña</title>
                    <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>
                </head>
                <body style='background-color: #f4f4f4;'>
                    <div class='container mt-5'>
                        <div class='row justify-content-center'>
                            <div class='col-md-8'>
                                <div class='card shadow-lg'>
                                    <div class='card-body'>
                                        <h2 class='card-title text-center mb-4' style='background-color: #007bff; color: white; font-weight: bold; padding: 10px;'>Restablecimiento de Contraseña</h2>
                                        <p class='card-text text-center'>Estimado Usuario, {nombre}</p>
                                        <p class='card-text text-center'>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta. Por favor, haz clic en el siguiente enlace para crear una nueva contraseña:</p>
                                        <div class='text-center'>
                                            <a href='{link}' class='btn btn-primary btn-lg'>Restablecer Contraseña</a>
                                        </div>
                                        <p class='card-text mt-3 text-center'>Si no solicitaste restablecer tu contraseña, puedes ignorar este correo electrónico.</p>
                                        <p class='card-text text-center mt-4'>Atentamente,<br>El equipo de soporte</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </body>
                </html>";
        }

        private string mail2(string nombre, string nuevaContraseña)
        {
            return $@"
                <!DOCTYPE html>
                <html lang='es'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>Cambio de Contraseña</title>
                    <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'>
                </head>
                <body style='background-color: #f4f4f4;'>
                    <div class='container mt-5'>
                        <div class='row justify-content-center'>
                            <div class='col-md-8'>
                                <div class='card shadow-lg'>
                                    <div class='card-body'>
                                        <h2 class='card-title text-center mb-4' style='background-color: #007bff; color: white; font-weight: bold; padding: 10px;'>Cambio de Contraseña</h2>
                                        <p class='card-text text-center'>Estimado Usuario, {nombre}</p>
                                        <p class='card-text text-center'>Has cambiado tu contraseña de forma correcta. Tu nueva contraseña es la siguiente:</p>
                                        <p class='card-text text-center' style='font-size: 1.5rem; font-weight: bold; color: #007bff;'>{nuevaContraseña}</p>
                                        <p class='card-text mt-3 text-center'>Te recomendamos que guardes esta información en un lugar seguro.</p>
                                        <p class='card-text text-center mt-4'>Atentamente,<br>El equipo de soporte</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </body>
                </html>";
        }
    }
}
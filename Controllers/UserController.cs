using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using eventosApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Net.Sockets;

namespace eventosApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IConfiguration _config;

        public UserController(DataContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }



        // GET api/user/--------------------------------------------------------------
        [HttpGet("")]
        [Authorize]
        public async Task<IActionResult> GetUser()
        {
            var emailClaim = User.FindFirst(ClaimTypes.Name)?.Value;
            if (emailClaim == null)
                return Unauthorized();

            var user = await _context.Users
                .AsNoTracking()
                .Where(u => u.Email == emailClaim)
                .Select(u => new
                {
                    u.Id,
                    u.Username,
                    u.Email,
                    Role = u.Role.ToString()
                })
                .FirstOrDefaultAsync();

            if (user == null)
                return NotFound("Usuario no encontrado.");

            return Ok(user);
        }

        // PUT api/user/update
        [HttpPut("update")]
        [Authorize]
        public async Task<IActionResult> UpdateUser([FromForm] UpdateUserModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var emailClaim = User.FindFirst(ClaimTypes.Name)?.Value;
            if (emailClaim == null)
                return Unauthorized();

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == emailClaim);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            // Verificar si están presentes contraseña actual y nueva
            if (!string.IsNullOrEmpty(model.CurrentPassword) || !string.IsNullOrEmpty(model.NewPassword))
            {
                // Deben venir ambas
                if (string.IsNullOrEmpty(model.CurrentPassword) || string.IsNullOrEmpty(model.NewPassword))
                    return BadRequest("Para cambiar la contraseña se debe enviar la contraseña actual y la nueva.");

                // Calcular hash de la contraseña actual
                var currentHashed = Convert.ToBase64String(
                    KeyDerivation.Pbkdf2(
                        password: model.CurrentPassword,
                        salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                        prf: KeyDerivationPrf.HMACSHA1,
                        iterationCount: 1000,
                        numBytesRequested: 256 / 8
                    )
                );

                if (user.PasswordHash != currentHashed)
                    return BadRequest("La contraseña actual es incorrecta.");

                // Verificar que la nueva contraseña no sea igual a la actual
                var newHashedCompare = Convert.ToBase64String(
                    KeyDerivation.Pbkdf2(
                        password: model.NewPassword,
                        salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                        prf: KeyDerivationPrf.HMACSHA1,
                        iterationCount: 1000,
                        numBytesRequested: 256 / 8
                    )
                );
                if (newHashedCompare == currentHashed)
                    return BadRequest("La nueva contraseña no puede ser igual a la actual.");

                // Asignar el nuevo hash
                user.PasswordHash = newHashedCompare;
            }

            // Si cambió el email, verificar que no exista otro usuario con ese email
            if (!string.IsNullOrWhiteSpace(model.Email) && model.Email != user.Email)
            {
                var exists = await _context.Users.AnyAsync(u => u.Email == model.Email);
                if (exists)
                    return BadRequest("Ya existe otro usuario con ese correo.");

                user.Email = model.Email;
            }

            // Actualizar username si cambió
            if (!string.IsNullOrWhiteSpace(model.Username) && model.Username != user.Username)
            {
                user.Username = model.Username;
            }

            await _context.SaveChangesAsync();
            return Ok("Usuario actualizado correctamente.");
        }

        // GET api/user/all
        [HttpGet("all")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> GetAllUsers(int pageNumber = 1, int pageSize = 10)
        {
            try
            {
                var totalRegistros = await _context.Users.CountAsync();

                var users = await _context.Users
                    .AsNoTracking()
                    .OrderBy(u => u.Role == Role.Administrador ? 0 :
                                  u.Role == Role.Organizador ? 1 : 2)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .Select(u => new
                    {
                        u.Id,
                        u.Username,
                        u.Email,
                        Role = u.Role.ToString()
                    })
                    .ToListAsync();

                var response = new PaginacionResponse<object>
                {
                    TotalRegistros = totalRegistros,
                    Datos = users.Cast<object>().ToList()
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al obtener la lista de usuarios.",
                    error = ex.Message
                });
            }
        }


        [HttpPut("role/{id}")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> UpdateUserRole(int id, [FromForm] Role newRole)
        {
            // Buscar al usuario por su Id
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
            {
                return NotFound("Usuario no encontrado.");
            }

            // Verificar si el rol es diferente para evitar una actualización innecesaria
            if (user.Role == newRole)
            {
                return Ok("El rol del usuario ya es el especificado. No se realizaron cambios.");
            }

            // Asignar el nuevo rol y guardar los cambios
            user.Role = newRole;
            await _context.SaveChangesAsync();

            return Ok($"Rol del usuario {user.Username} actualizado a {user.Role}.");
        }

        // DELETE api/user/{id} ---------------------------------------------------------------------------
        [HttpDelete("{id}")]
        [Authorize(Roles = "Administrador")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return Ok("Usuario eliminado correctamente.");
        }



        /*

        // GET api/user/{id} ----------------------------------------------------------------
        [HttpGet("{id}")]
        [Authorize]
        public async Task<IActionResult> GetUserId(int id)
        {
            // Buscar el usuario por ID
            var user = await _context.Users
                .AsNoTracking()  // No se realiza seguimiento de cambios en este caso
                .Where(u => u.Id == id)
                .Select(u => new
                {
                    u.Id,
                    u.Username,
                    u.Email,
                    Role = u.Role.ToString()
                })
                .FirstOrDefaultAsync();

            if (user == null)
                return NotFound("Usuario no encontrado.");

            return Ok(user);
        }*/

        /*
        // PUT api/user/update/{id} -----------------------------------------------------------------------
        [HttpPut("update/{id}")]
        [Authorize(Roles = "Administrador")]
        public async Task<IActionResult> UpdateUserAdmin(int id, [FromForm] UpdateUserAdminModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            // Si se envía email diferente, verificar unicidad
            if (!string.IsNullOrWhiteSpace(model.Email) && model.Email != user.Email)
            {
                var exists = await _context.Users.AnyAsync(u => u.Email == model.Email && u.Id != id);
                if (exists)
                    return BadRequest("Ya existe otro usuario con ese correo.");

                user.Email = model.Email;
            }

            // Actualizar username si viene
            if (!string.IsNullOrWhiteSpace(model.Username) && model.Username != user.Username)
            {
                user.Username = model.Username;
            }

            // Actualizar rol si viene
            if (model.Role.HasValue && model.Role.Value != user.Role)
            {
                user.Role = model.Role.Value;
            }

            // Si el admin quiere cambiar la contraseña
            if (!string.IsNullOrEmpty(model.NewPassword))
            {
                // Calcular hash de la nueva contraseña
                var newHashed = Convert.ToBase64String(
                    KeyDerivation.Pbkdf2(
                        password: model.NewPassword,
                        salt: Encoding.ASCII.GetBytes(_config["Salt"]),
                        prf: KeyDerivationPrf.HMACSHA1,
                        iterationCount: 1000,
                        numBytesRequested: 256 / 8
                    )
                );
                user.PasswordHash = newHashed;
            }

            await _context.SaveChangesAsync();
            return Ok("Usuario actualizado correctamente.");
        }
*/
    }
}
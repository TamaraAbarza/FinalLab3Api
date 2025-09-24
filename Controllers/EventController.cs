using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using eventosApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace eventosApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EventController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IConfiguration _config;
        private readonly IWebHostEnvironment _environment;
        public EventController(DataContext context, IConfiguration config, IWebHostEnvironment env)
        {
            _context = context;
            _config = config;
            _environment = env;
        }

        // POST api/event/create -------------------------------------------------------------------
        [HttpPost("create")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> CreateEvent([FromForm] Event model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (model.Date < DateTime.Now)
            {
                return BadRequest("La fecha y hora del evento deben ser mayores o iguales a la fecha y hora actual.");
            }

            try
            {
                string? imagenUrl = null;
                if (model.ImagenFile != null)
                {
                    imagenUrl = await ProcesarCargaImagen(model.ImagenFile);

                    if (!string.IsNullOrEmpty(imagenUrl))
                    {
                        model.ImageUrl = imagenUrl;
                    }
                }
                var nuevoEvento = new Event
                {
                    Name = model.Name,
                    Date = model.Date,
                    Location = model.Location,
                    Description = model.Description,
                    ImageUrl = model.ImageUrl
                };

                _context.Events.Add(nuevoEvento);
                await _context.SaveChangesAsync();
                return Ok("Evento creado exitosamente.");
            }
            catch (Exception ex)
            {
                return BadRequest($"Ocurrió un error al crear el evento: {ex.Message}");
            }
        }

        // PUT api/event/update{id} -------------------------------------------------
        [HttpPut("update/{id}")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> UpdateEvent(int id, [FromForm] Event model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ev = await FindEventById(id);
                if (ev == null)
                    return NotFound("Evento no encontrado.");

                ev.Name = model.Name;
                ev.Date = model.Date;
                ev.Location = model.Location;
                ev.Description = model.Description;

                if (model.ImagenFile != null && model.ImagenFile.Length > 0)
                {
                    string? nuevaImagenUrl = await ProcesarCargaImagen(model.ImagenFile);
                    if (!string.IsNullOrEmpty(nuevaImagenUrl))
                    {
                        ev.ImageUrl = nuevaImagenUrl;
                    }
                }

                _context.Events.Update(ev);
                await _context.SaveChangesAsync();

                return Ok("Evento modificado exitosamente.");
            }
            catch (Exception ex)
            {
                return BadRequest($"Ocurrió un error al modificar el evento: {ex.Message}");
            }
        }

        // DELETE api/event/{id} ----------------------------------------------------------------------
        [HttpDelete("delete/{id}")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> DeleteEvent(int id)
        {
            try
            {
                var ev = await FindEventById(id);
                if (ev == null)
                    return NotFound("Evento no encontrado.");

                var participations = _context.Participations.Where(p => p.EventId == id);
                _context.Participations.RemoveRange(participations);

                _context.Events.Remove(ev);
                await _context.SaveChangesAsync();

                return Ok("Evento y participaciones relacionadas eliminados exitosamente.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ocurrió un error al eliminar el evento: {ex.Message}");
            }
        }



        // GET api/event/proximos -----------------------------------------------------------------
        [HttpGet("proximos")]
        [Authorize]
        public async Task<IActionResult> GetProxEvents([FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
        {
            try
            {
                if (pageNumber < 1) pageNumber = 1;
                if (pageSize < 1) pageSize = 10;

                var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
                var today = DateTime.Today;

                var query = _context.Events
                                    .AsNoTracking()
                                    .Where(e => e.Date.Date >= today)
                                    .OrderBy(e => e.Date);

                var totalRegistros = await query.CountAsync();

                var eventos = await query
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                var ids = eventos.Select(e => e.Id).ToList();
                var participations = await _context.Participations
                    .Where(p => ids.Contains(p.EventId) && p.UserId == userId)
                    .Select(p => p.EventId)
                    .ToListAsync();

                foreach (var ev in eventos)
                {
                    ev.IsParticipating = participations.Contains(ev.Id);
                }

                var response = new PaginacionResponse<Event>
                {
                    TotalRegistros = totalRegistros,
                    Datos = eventos
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al obtener los próximos eventos.",
                    error = ex.Message
                });
            }
        }

        [HttpGet("all")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> GetAllEvents(
     [FromQuery] int pageNumber = 1,
     [FromQuery] int pageSize = 10,
     [FromQuery] string filter = "all") // "all" | "past" | "future"
        {
            try
            {
                if (pageNumber < 1) pageNumber = 1;
                if (pageSize < 1) pageSize = 10;

                var today = DateTime.Today;

                IQueryable<Event> query = _context.Events.AsNoTracking();

                switch ((filter ?? "all").Trim().ToLowerInvariant())
                {
                    case "past":
                        query = query.Where(e => e.Date.Date < today)
                                     .OrderByDescending(e => e.Date);
                        break;

                    case "future":
                        query = query.Where(e => e.Date.Date >= today)
                                     .OrderBy(e => e.Date);
                        break;

                    default:
                        query = query.OrderByDescending(e => e.Date);
                        break;
                }

                var totalRegistros = await query.CountAsync();

                var eventos = await query
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                var response = new PaginacionResponse<Event>
                {
                    TotalRegistros = totalRegistros,
                    Datos = eventos
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al obtener la lista de eventos.",
                    error = ex.Message
                });
            }
        }

        //------------------------------------------------------------------------------------------

        //verificar si un evento existe
        private async Task<Event?> FindEventById(int id)
        {
            try
            {
                return await _context.Events.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id);
            }
            catch
            {
                return null;
            }
        }


        //para cargar imagen 
        private async Task<string> ProcesarCargaImagen(IFormFile imagenFile)
        {
            if (imagenFile != null && imagenFile.Length > 0)
            {
                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");

                if (!Directory.Exists(uploadsFolder))
                {
                    Directory.CreateDirectory(uploadsFolder);
                }

                var uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(imagenFile.FileName);
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await imagenFile.CopyToAsync(fileStream);
                }

                return "uploads/" + uniqueFileName; // URL de la imagen cargada
            }

            return null;
        }



    }
}

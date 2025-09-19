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


using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System.IO;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace eventosApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ParticipationController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IConfiguration _config;

        public ParticipationController(DataContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }

        // POST api/participation/create -------------------------------------------------------------------

        [HttpPost("create/{eventId}")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> CreateParticipation(int eventId)
        {
            try
            {
                // Obtener el email del usuario desde el token
                var userEmail = User.Identity?.Name;

                if (string.IsNullOrEmpty(userEmail))
                    return Unauthorized(new { message = "No se pudo identificar al usuario." });

                // Buscar el usuario en la base de datos
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
                if (user == null)
                    return Unauthorized(new { message = "Usuario no encontrado." });

                // Validar que el evento exista
                var eventEntity = await _context.Events.FindAsync(eventId);
                if (eventEntity == null)
                    return NotFound(new { message = "Evento no encontrado." });

                // Validar que el evento no sea pasado
                if (eventEntity.Date.Date < DateTime.Today)
                    return BadRequest(
                        new { message = "No está permitido inscribirse en un evento pasado." }
                    );

                // Verificar si el usuario ya está inscrito en este evento
                var existingParticipation = await _context.Participations.FirstOrDefaultAsync(p =>
                    p.UserId == user.Id && p.EventId == eventId
                );

                if (existingParticipation != null)
                    return BadRequest(new { message = "Ya estás inscrito en este evento." });

                // Crear nueva participación
                var participation = new Participation
                {
                    UserId = user.Id,
                    EventId = eventId,
                    IsConfirmed = false // Inicialmente no confirmada
                };

                _context.Participations.Add(participation);
                await _context.SaveChangesAsync();

                return Ok(
                    new { message = "Participación registrada exitosamente.", participation }
                );
            }
            catch (Exception ex)
            {
                return StatusCode(
                    500,
                    new
                    {
                        message = "Ocurrió un error al registrar la participación.",
                        error = ex.Message
                    }
                );
            }
        }

        //confirmar participacion
        // PUT api/participation/confirm{id} -------------------------------------------------
        [HttpPut("confirm/{id}")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> ConfirmParticipation(int id, [FromBody] bool isConfirmed)
        {
            try
            {
                // Buscar la participación por ID
                var participation = await _context.Participations
                    .Include(p => p.Event)
                    .Include(p => p.User)
                    .FirstOrDefaultAsync(p => p.Id == id);

                if (participation == null)
                    return NotFound(new { message = "Participación no encontrada." });

                // Validar que no se pueda confirmar si el evento aún no ha ocurrido
                if (isConfirmed && participation.Event.Date > DateTime.Now)
                {
                    return BadRequest(new { message = "No se puede confirmar la participación en un evento que aún no ha ocurrido." });
                }

                // Actualizar el estado
                participation.IsConfirmed = isConfirmed;

                _context.Participations.Update(participation);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    message = $"Participación {(isConfirmed ? "confirmada" : "sin confirmar")} exitosamente.",
                    participation
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al confirmar la participación.",
                    error = ex.Message
                });
            }
        }

        // DELETE api/participation/{id} ----------------------------------------------------------------------
        [HttpDelete("delete/{id}")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> DeleteParticipation(int id)
        {
            try
            {
                var participation = await _context.Participations.FindAsync(id);

                if (participation == null)
                    return NotFound(new { message = "Participación no encontrada." });

                _context.Participations.Remove(participation);
                await _context.SaveChangesAsync();

                return Ok(new { message = "Participación eliminada exitosamente." });
            }
            catch (Exception ex)
            {
                return StatusCode(
                    500,
                    new
                    {
                        message = "Ocurrió un error al eliminar la participación.",
                        error = ex.Message
                    }
                );
            }
        }


        // DELETE api/participation/delete-by-event/{eventId}
        [HttpDelete("delete-by-event/{eventId}")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> DeleteParticipationByEvent(int eventId)
        {
            try
            {
                //usuario logueado
                var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));

                //participación del usuario del evento id
                var participation = await _context.Participations
                    .FirstOrDefaultAsync(p => p.EventId == eventId && p.UserId == userId);

                if (participation == null)
                    return NotFound(new { message = "Participación del usuario en este evento no encontrada." });

                _context.Participations.Remove(participation);
                await _context.SaveChangesAsync();

                return Ok(new { message = "Participación eliminada exitosamente." });
            }
            catch (Exception ex)
            {
                return StatusCode(
                    500,
                    new
                    {
                        message = "Ocurrió un error al eliminar la participación.",
                        error = ex.Message
                    }
                );
            }
        }

        //obtener una lista de todas las participaciones  --------- Borrrar??? 
        // GET api/participation/all?pageNumber=1&pageSize=10
        // Roles: Organizador, Administrador
        [HttpGet("all")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> GetAllParticipations([FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
        {
            try
            {
                if (pageNumber < 1) pageNumber = 1;
                if (pageSize < 1) pageSize = 10;

                var query = _context.Participations
                                    .AsNoTracking()
                                    .Include(p => p.User)
                                    .Include(p => p.Event)
                                    .OrderBy(p => p.Event.Date); // misma lógica: orden por fecha del evento

                var totalRegistros = await query.CountAsync();

                var participations = await query
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                var response = new PaginacionResponse<Participation>
                {
                    TotalRegistros = totalRegistros,
                    Datos = participations
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(
                    500,
                    new
                    {
                        message = "Ocurrió un error al obtener las participaciones.",
                        error = ex.Message
                    }
                );
            }
        }


        //obtener las participaciones de un usuario
        // GET api/participation/user
        [HttpGet("user")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> GetUserParticipations(int pageNumber = 1, int pageSize = 10)
        {
            var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);

            try
            {
                var query = _context.Participations
                    .Where(p => p.UserId == userId && p.IsConfirmed)
                    .Include(p => p.Event);

                var totalRegistros = await query.CountAsync();

                var participations = await query
                    .OrderBy(p => p.Event.Date)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .Select(p => new
                    {
                        p.Event.Id,
                        p.Event.Name,
                        p.Event.Date,
                        p.Event.Location,
                        p.Event.Description
                    })
                    .ToListAsync();

                if (!participations.Any())
                    return NotFound(new { message = "No tenes eventos confirmados registrados." });

                var response = new PaginacionResponse<object>
                {
                    TotalRegistros = totalRegistros,
                    Datos = participations.Cast<object>().ToList()
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al obtener tus eventos confirmados.",
                    error = ex.Message
                });
            }
        }

        //obtener los proximos eventos inscriptos del usuario
        // GET api/participation/upcoming
        [HttpGet("upcoming")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> GetUpcomingParticipations(int pageNumber = 1, int pageSize = 10)
        {
            var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);

            try
            {
                var query = _context.Participations
                    .Where(p => p.UserId == userId && p.Event.Date >= DateTime.Now)
                    .Include(p => p.Event);

                var totalRegistros = await query.CountAsync();

                var upcomingEvents = await query
                    .OrderBy(p => p.Event.Date)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .Select(p => new
                    {
                        p.Event.Id,
                        p.Event.Name,
                        p.Event.Date,
                        p.Event.Location,
                        p.Event.Description
                    })
                    .ToListAsync();

                if (!upcomingEvents.Any())
                {
                    return NotFound(new
                    {
                        message = "No tienes eventos futuros confirmados registrados."
                    });
                }

                var response = new PaginacionResponse<object>
                {
                    TotalRegistros = totalRegistros,
                    Datos = upcomingEvents.Cast<object>().ToList()
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al obtener tus eventos futuros confirmados.",
                    error = ex.Message
                });
            }
        }

        //obtner las participaciones de un evento
        // GET api/participation/event/{id}?pageNumber=1&pageSize=10
        // Obtener las participaciones de un evento (paginado). Roles: Organizador, Administrador
        [HttpGet("event/{id}")]
        [Authorize(Roles = "Organizador,Administrador")]
        public async Task<IActionResult> GetParticipationsByEvent(int id, [FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
        {
            try
            {
                if (pageNumber < 1) pageNumber = 1;
                if (pageSize < 1) pageSize = 10;

                var query = _context.Participations
                                    .AsNoTracking()
                                    .Where(p => p.EventId == id)
                                    .Include(p => p.User)
                                    .Include(p => p.Event)
                                    .OrderBy(p => p.User.Id); // ordenar por usuario (o cambiá a lo que prefieras)

                var totalRegistros = await query.CountAsync();

                var participations = await query
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                var response = new PaginacionResponse<Participation>
                {
                    TotalRegistros = totalRegistros,
                    Datos = participations
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(
                    500,
                    new
                    {
                        message = "Ocurrió un error al obtener los participantes del evento.",
                        error = ex.Message
                    }
                );
            }
        }

        //obtener certificado
        // GET api/participation/certificate/id ------------------------------------------------------------------------
        [HttpGet("certificate/{eventId}")]
        [Authorize(Roles = "Usuario,Organizador,Administrador")]
        public async Task<IActionResult> GetCertificate(int eventId)
        {
            var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);

            try
            {
                var participation = await _context.Participations
                    .Include(p => p.Event)
                    .Include(p => p.User)
                    .FirstOrDefaultAsync(p => p.EventId == eventId && p.UserId == userId);

                if (participation == null)
                    return NotFound(new { message = "No se encontró participación para este evento y usuario." });

                if (!participation.IsConfirmed)
                    return BadRequest(new { message = "No puedes obtener el certificado, tu participación no está confirmada." });

                var eventName = participation.Event.Name;
                var userName = participation.User.Username;
                var eventDate = participation.Event.Date.ToString("dd 'de' MMMM 'de' yyyy");
                var eventLocation = participation.Event.Location;

                using var stream = new MemoryStream();

                Document.Create(container =>
                {
                    container.Page(page =>
                    {
                        page.Size(PageSizes.A4);
                        page.Margin(50);
                        page.PageColor(Colors.White);
                        page.DefaultTextStyle(x => x.FontSize(16).FontColor(Colors.Black));

                        page.Content()
                            .Padding(40)
                            .Background(Colors.White)
                            .Column(col =>
                            {
                                col.Spacing(20);

                                col.Item().AlignCenter().Text("CERTIFICADO DE PARTICIPACIÓN")
                                    .FontSize(28)
                                    .Bold()
                                    .FontColor(Colors.Grey.Darken3);

                                col.Item().Container().PaddingVertical(10)
                                    .LineHorizontal(1).LineColor(Colors.Grey.Lighten2);

                                col.Item().AlignCenter().Text("Se otorga el presente certificado a")
                                    .FontSize(16)
                                    .FontColor(Colors.Grey.Darken1);

                                col.Item().AlignCenter().Text(userName)
                                    .FontSize(26)
                                    .SemiBold()
                                    .FontColor(Colors.Grey.Darken4);

                                col.Item().AlignCenter().Text($"por su valiosa participación en el evento")
                                    .FontSize(16)
                                    .FontColor(Colors.Grey.Darken1);

                                col.Item().AlignCenter().Text($"“{eventName}”")
                                    .FontSize(20)
                                    .Italic()
                                    .FontColor(Colors.Grey.Darken3);

                                col.Item().AlignCenter().Text($"realizado el día {eventDate} en {eventLocation}.")
                                    .FontSize(14)
                                    .FontColor(Colors.Grey.Darken2);

                                col.Item().PaddingTop(60).AlignCenter().Column(signatureCol =>
                                {
                                    signatureCol.Item().Text("eventos ULP")
                                        .FontSize(18)
                                        .Bold()
                                        .FontColor(Colors.Grey.Darken3)
                                        .AlignCenter();

                                    signatureCol.Item().Container().PaddingVertical(15)
                                        .LineHorizontal(1).LineColor(Colors.Grey.Lighten3);

                                    signatureCol.Item().Text("Organización del Evento")
                                        .FontSize(12)
                                        .Italic()
                                        .FontColor(Colors.Grey.Darken1)
                                        .AlignCenter();
                                });

                                col.Item().PaddingTop(40).AlignCenter().Text($"Generado el {DateTime.Now:dd/MM/yyyy}")
                                    .FontSize(10)
                                    .Italic()
                                    .FontColor(Colors.Grey.Darken2);
                            });
                    });
                }).GeneratePdf(stream);

                stream.Position = 0;

                return File(stream.ToArray(), "application/pdf", $"Certificado_{userName}_{eventId}.pdf");
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    message = "Ocurrió un error al generar el certificado.",
                    error = ex.Message,
                    stack = ex.StackTrace
                });
            }
        }
    }



}

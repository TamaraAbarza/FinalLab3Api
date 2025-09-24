using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace eventosApi.Models
{
    // Enum para los roles
    public enum Role
    {
        Usuario,
        Organizador,
        Administrador
    }
    public class User
    {
        public int Id { get; set; }

        [Required]
        public string Username { get; set; } = string.Empty;

        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        public Role Role { get; set; } = Role.Usuario;

         //navegación para las participaciones del usuario
        public ICollection<Participation> Participations { get; set; }

        public override string ToString()
        {
            return Role.ToString();
        }
    }
}
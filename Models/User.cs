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
        Usuario, // Rol de usuario normal
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
        public Role Role { get; set; } = Role.Usuario; // Valor predeterminado: Usuario

        public override string ToString()
        {
            return Role.ToString(); // Devuelve el nombre del rol en lugar del valor numérico
        }
    }
}
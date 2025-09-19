using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace eventosApi.Models
{
    public class UpdateUserModel
    {
        public string? Username { get; set; }

        [EmailAddress]
        public string? Email { get; set; }

        //cambiar contraseña:
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
    }
}
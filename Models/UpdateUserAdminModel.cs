using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace eventosApi.Models
{
    public class UpdateUserAdminModel
    {
            [EmailAddress]
            public string? Email { get; set; }

            public string? Username { get; set; }

            public Role? Role { get; set; }

            public string? NewPassword { get; set; }
    }
}
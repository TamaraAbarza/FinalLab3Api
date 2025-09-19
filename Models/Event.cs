using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations.Schema;

namespace eventosApi.Models
{
    public class Event
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [Required]
        public DateTime Date { get; set; }

        [Required]
        [StringLength(200)]
        public string Location { get; set; } = string.Empty;

        public string? Description { get; set; } = string.Empty;

        [StringLength(300)]
        public string? ImageUrl { get; set; }

        [NotMapped]
        public IFormFile? ImagenFile { get; set; }

        [NotMapped]
        public bool IsParticipating { get; set; }
    }
}

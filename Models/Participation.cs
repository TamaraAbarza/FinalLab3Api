using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace eventosApi.Models
{
    public class Participation
    {
        public int Id { get; set; }

        [Required]
        public bool IsConfirmed { get; set; }

        // Relación con el modelo User
        [ForeignKey("UserId")]
        public int UserId { get; set; }
        public User User { get; set; }

        // Relación con el modelo Event
        [ForeignKey("EventId")]
        public int EventId { get; set; }
        public Event Event { get; set; }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace eventosApi.Models
{
     public class PaginacionResponse<T>
    {
        public int TotalRegistros { get; set; }
        public List<T> Datos { get; set; }
    }
}
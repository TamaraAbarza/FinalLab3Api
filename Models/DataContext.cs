using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using eventosApi.Models;
using Microsoft.EntityFrameworkCore;


namespace eventosApi.Models
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options)
            : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<Event> Events { get; set; }
        public DbSet<Participation> Participations { get; set; }

    }
}
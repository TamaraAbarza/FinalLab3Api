using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using eventosApi;
using eventosApi.Models;
using QuestPDF.Infrastructure;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
builder.WebHost.UseUrls("http://localhost:5000", "https://localhost:5001", "http://*:5000", "https://*:5001");

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// DataContext entity
#pragma warning disable CS8604 // Possible null reference argument.
builder.Services.AddDbContext<DataContext>(
  options => options.UseMySQL(
	configuration["ConnectionStrings:DefaultConnection"]));
#pragma warning restore CS8604 // Possible null reference argument.

// Autenticación con JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(options => // La API valida con token
	{
		options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = configuration["TokenAuthentication:Issuer"],
			ValidAudience = configuration["TokenAuthentication:Audience"],
			IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(
			configuration["TokenAuthentication:SecretKey"])),
		};

		// Opción extra para usar el token en el hub y otras peticiones sin encabezado (enlaces, src de img, etc.)
		options.Events = new JwtBearerEvents
		{
			OnMessageReceived = context =>
			{
				// Leer el token desde el query string
				var accessToken = context.Request.Query["access_token"];
				// Si el request es para el Hub u otra ruta seleccionada...
				var path = context.HttpContext.Request.Path;
				if (!string.IsNullOrEmpty(accessToken) &&
			(path.StartsWithSegments("/chatsegurohub") ||
			path.StartsWithSegments("/api/propietario/reset") ||
			path.StartsWithSegments("/api/propietario/token")))
				{
					// Reemplazar las URLs por las necesarias
					context.Token = accessToken;
				}
				return Task.CompletedTask;
			}
		};
	});

// Establecer licencia
QuestPDF.Settings.License = LicenseType.Community;

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

// Habilitar CORS
app.UseCors(x => x
  .AllowAnyOrigin()
  .AllowAnyMethod()
  .AllowAnyHeader());

app.UseStaticFiles();
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(builder.Environment.WebRootPath, "uploads")),
    RequestPath = "/uploads"
});

app.UseAuthentication();  // Usar autenticación basada en JWT
app.UseAuthorization();

app.MapControllers();

app.Run();
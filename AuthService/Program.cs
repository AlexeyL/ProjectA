using AuthService.Extensions;
using AuthService.Middlewares;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// configure fluen validation
builder.Services.ConfigureFluentValidaton();

// add authentication and authorization
builder.Services.ConfigureAuthentication(builder.Configuration);
builder.Services.ConfigureAuthorization();

// configure automapper
builder.Services.ConfigureAutoMapper();

// configure dependency injection
builder.Services.ConfigureDependency();

// remove defaul logging providers
builder.Logging.ClearProviders();

// set up serilog
var logger = new LoggerConfiguration()
  .ReadFrom.Configuration(builder.Configuration)
  .Enrich.FromLogContext()
  .WriteTo.Console()
  .CreateLogger();

// register serilog
builder.Logging.AddSerilog(logger);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseGlobalErrorHandler();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

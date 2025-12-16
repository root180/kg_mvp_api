// ==========================================================================
// PROGRAM.CS — Application Entry Point
// KeiroGenesis API (MVP)
// DI Registration, Middleware, Startup Configuration
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Controllers.V1;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.IdentityModel.Tokens.Jwt;

using System.Security.Cryptography;
using System.Text;
using static KeiroGenesis.API.Core.Database.PostgreSqlConnectionFactory;

var builder = WebApplication.CreateBuilder(args);

// ==========================================================================
// SERILOG CONFIGURATION (Read from appsettings.json ONLY)
// ==========================================================================

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());
// ✅ REMOVED: .WriteTo.Console() and .WriteTo.File() 
// ✅ Now ALL logging config comes from appsettings.json

// ==========================================================================
// DATABASE
// ==========================================================================

// Register Dapper vector type handler (pgvector)
SqlMapper.AddTypeHandler(new VectorTypeHandler());

builder.Services.AddSingleton<IDbConnectionFactory, PostgreSqlConnectionFactory>();

// ==========================================================================
// MODULES — Repository + Service Registration
// ==========================================================================

// Auth
builder.Services.AddScoped<KeiroGenesis.API.Repositories.AuthRepository>();
builder.Services.AddScoped<KeiroGenesis.API.Services.AuthService>();

// Health
builder.Services.AddScoped<HealthRepository>();
builder.Services.AddScoped<HealthService>();

// Tenant
builder.Services.AddScoped<TenantRepository>();
builder.Services.AddScoped<TenantService>();

// User
builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<UserService>();

// Clone
builder.Services.AddScoped<CloneRepository>();
builder.Services.AddScoped<CloneService>();

// Actor
builder.Services.AddScoped<ActorRepository>();
builder.Services.AddScoped<ActorService>();

// Social
builder.Services.AddScoped<SocialRepository>();
builder.Services.AddScoped<SocialService>();

// Messaging
builder.Services.AddScoped<MessagingRepository>();
builder.Services.AddScoped<MessagingService>();

// RAG
builder.Services.AddScoped<RagRepository>();
builder.Services.AddScoped<RagService>();

// Capability
builder.Services.AddScoped<CapabilityRepository>();
builder.Services.AddScoped<CapabilityService>();

// Management
builder.Services.AddScoped<UserManagementRepository>();
builder.Services.AddScoped<UserManagementService>();

//CloneWizard
builder.Services.AddScoped<CloneWizardRepository>();
builder.Services.AddScoped<CloneWizardService>();

//Clone Service
builder.Services.AddScoped<CloneService>();
builder.Services.AddScoped<CloneRepository>();




// ==========================================================================
// AUTHENTICATION (JWT/AUTH BEARER + PREAUTH) — SYMMETRIC ONLY
// ==========================================================================

var jwtSecret = builder.Configuration["Auth:Secret"]
    ?? throw new InvalidOperationException("Auth:Secret is required");

var jwtIssuer = builder.Configuration["Auth:Issuer"]
    ?? throw new InvalidOperationException("Auth:Issuer is required");

var jwtAudience = builder.Configuration["Auth:Audience"]
    ?? throw new InvalidOperationException("Auth:Audience is required");

var preAuthAudience = builder.Configuration["Auth:PreAuthAudience"]
    ?? throw new InvalidOperationException("Auth:PreAuthAudience is required");

var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = "Bearer";
        options.DefaultChallengeScheme = "Bearer";
    })

    // ----------------------------------------------------------------------
    // MAIN ACCESS TOKEN (Bearer)
    // ----------------------------------------------------------------------
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = signingKey,

            ClockSkew = TimeSpan.FromMinutes(1),

            // ✅ IMPORTANT: make claims consistent across the app
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };

        // ✅ OPTIONAL: helps you see real auth failures in logs
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("JwtBearer");

                logger.LogError(context.Exception, "Bearer token authentication failed");
                return Task.CompletedTask;
            }
        };
    })

    // ----------------------------------------------------------------------
    // PRE-AUTH TOKEN (Registration / Verification / MFA / Bootstrap)
    // ----------------------------------------------------------------------
    .AddJwtBearer("PreAuth", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            ValidIssuer = jwtIssuer,
            ValidAudience = preAuthAudience,
            IssuerSigningKey = signingKey,

            ClockSkew = TimeSpan.FromMinutes(1),

            // ✅ IMPORTANT: same claim mapping here too
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };

        // ✅ OPTIONAL: helps you see real auth failures in logs
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("JwtBearer");

                logger.LogError(context.Exception, "PreAuth token authentication failed");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();


// ==========================================================================
// API CONFIGURATION
// ==========================================================================

// Routing - Lowercase URLs for all controllers
builder.Services.AddRouting(options =>
{
    options.LowercaseUrls = true;
});

// Controllers
builder.Services.AddControllers();

// API Versioning
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
});

// Swagger / OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "KeiroGenesis API", Version = "v1" });

    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy
            .WithOrigins(
                builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                ?? new[] { "http://localhost:3000", "http://localhost:5173", "http://localhost:8080" }
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

// ==========================================================================
// BUILD APPLICATION
// ==========================================================================
var app = builder.Build();

// ==========================================================================
// MIDDLEWARE PIPELINE
// ==========================================================================

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "KeiroGenesis API v1");
    options.RoutePrefix = string.Empty;
});

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// ==========================================================================
// STARTUP MESSAGE
// ==========================================================================

app.Lifetime.ApplicationStarted.Register(() =>
{
    Log.Information("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    Log.Information("🚀 KeiroGenesis API Started Successfully");
    Log.Information("📝 Logs: Logs/keirogenesis-{Date}.log", DateTime.Now.ToString("yyyyMMdd"));
    Log.Information("📖 Swagger: http://localhost:8080");
    Log.Information("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
});

// ==========================================================================
// RUN
// ==========================================================================
try
{
    Log.Information("Starting KeiroGenesis API...");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
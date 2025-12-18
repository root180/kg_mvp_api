// ==========================================================================
// PROGRAM.CS — Application Entry Point
// KeiroGenesis API (MVP)
// DI Registration, Middleware, Startup Configuration
// ==========================================================================

using Dapper;
using KeiroGenesis.API.Controllers.V1;
using KeiroGenesis.API.Core.Database;
using KeiroGenesis.API.Core.Versioning;
using KeiroGenesis.API.GraphQL.Dashboard;
using KeiroGenesis.API.Repositories;
using KeiroGenesis.API.Services;
using KeiroGenesis.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using static KeiroGenesis.API.Core.Database.PostgreSqlConnectionFactory;

var builder = WebApplication.CreateBuilder(args);



// ============================================================
// Build Information Service
// ============================================================
var buildInfoService = new BuildInfoService(builder.Configuration, builder.Environment);
var appName = buildInfoService.GetDisplayName();



// ==========================================================================
// SERILOG CONFIGURATION (Read from appsettings.json ONLY)
// ==========================================================================

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

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
builder.Services.AddScoped<AuthRepository>();
builder.Services.AddScoped<AuthService>();

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

// Clone Wizard
builder.Services.AddScoped<CloneWizardRepository>();
builder.Services.AddScoped<CloneWizardService>();


// Email Provider
builder.Services.AddScoped<IEmailProvider, EmailService>();


// ==========================================================================
// AUTHENTICATION (JWT / PRE-AUTH) — SYMMETRIC
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
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };
    })
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
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization();

// REQUIRED for GraphQL + DashboardGraphQLService
builder.Services.AddHttpContextAccessor();

// ==========================================================================
// API CONFIGURATION
// ==========================================================================

builder.Services.AddRouting(o => o.LowercaseUrls = true);
builder.Services.AddControllers();

builder.Services.AddApiVersioning(o =>
{
    o.DefaultApiVersion = new ApiVersion(1, 0);
    o.AssumeDefaultVersionWhenUnspecified = true;
    o.ReportApiVersions = true;
});

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new() { Title = "KeiroGenesis API", Version = "v1" });
});

// CORS
builder.Services.AddCors(o =>
{
    o.AddDefaultPolicy(p =>
        p.WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
            ?? new[] { "http://localhost:3000", "http://localhost:5173", "http://localhost:8080" })
         .AllowAnyHeader()
         .AllowAnyMethod()
         .AllowCredentials());
});

// ==========================================================================
// IDENTITY MODULE - MODERN NPGSQL DATA SOURCE (Npgsql 8.0+)
// ==========================================================================

var identityConnectionString = builder.Configuration.GetConnectionString("KeiroGenesisDb")
    ?? throw new InvalidOperationException("Connection string 'KeiroGenesisDb' not found");

var dataSourceBuilder = new NpgsqlDataSourceBuilder(identityConnectionString);

// Map all Identity module enums (MODERN APPROACH)
dataSourceBuilder.MapEnum<IdentityVerificationLevel>("auth.identity_verification_level");
dataSourceBuilder.MapEnum<AgeVerificationResult>("auth.age_verification_result");
dataSourceBuilder.MapEnum<VerificationMethod>("auth.verification_method");
dataSourceBuilder.MapEnum<VerificationStatus>("auth.verification_status");
dataSourceBuilder.MapEnum<ConsentType>("auth.consent_type");
dataSourceBuilder.MapEnum<VerificationProvider>("auth.verification_provider");

var identityDataSource = dataSourceBuilder.Build();



// Then register services
builder.Services.AddScoped<IdentitySignalsRepository>();
builder.Services.AddScoped<IdentitySignalsService>();
// ==========================================================================
// GRAPHQL — SERVICE REGISTRATION (ONLY HERE)
// ==========================================================================

builder.Services.AddDashboardGraphQL();
builder.Services.AddDashboardGraphQLServer();

// ==========================================================================
// BUILD APPLICATION
// ==========================================================================

var app = builder.Build();

// ==========================================================================
// MIDDLEWARE PIPELINE
// ==========================================================================

app.UseSwagger();
app.UseSwaggerUI(o =>
{
    o.SwaggerEndpoint("/swagger/v1/swagger.json", "KeiroGenesis API v1");
    o.RoutePrefix = string.Empty;
});

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}



// Version/build headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-API-Version", "1.0");
    context.Response.Headers.Add("X-Build-Number", buildInfoService.GetBuildInfo().BuildNumber);
    context.Response.Headers.Add("X-API-Deprecated", "false");
    await next();
});



app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// GRAPHQL ENDPOINT
app.MapGraphQL("/graphql/dashboard");

// ==========================================================================
// STARTUP LOGGING
// ==========================================================================

app.Lifetime.ApplicationStarted.Register(() =>
{
    Log.Information("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    Log.Information("🚀 KeiroGenesis API Started Successfully");
    Log.Information("📖 Swagger: http://localhost:8080");
    Log.Information("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
});



// ============================================================
// Optional Startup Email Notification (Non-blocking)
// ============================================================
_ = Task.Run(async () =>
{
try
{
// Wait for app to start and be ready
await Task.Delay(3000);

using var scope = app.Services.CreateScope();
var emailService = scope.ServiceProvider.GetRequiredService<IEmailProvider>();

var result = await emailService.SendEmailAsync(
    "teckhne@gmail.com",
    "✅ KeiroGenesis API Started",
    "KeiroGenesis API deployment successful - plain text version",
    "<h3>KeiroGenesis API deployment successful 🚀</h3>"
);

if (result)
Log.Information("Startup email notification sent successfully");
else
Log.Warning("Startup email notification failed to send");
}
catch (Exception ex)
{
Log.Warning(ex, "Failed to send startup email - this is non-critical");
}
});


// ==========================================================================
// RUN
// ==========================================================================

try
{
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

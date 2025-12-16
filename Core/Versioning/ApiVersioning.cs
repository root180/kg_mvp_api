// File: KeiroGenesis.API/API/Versioning/ApiVersioning.cs
// Location: Add to API/Versioning folder


using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.AspNetCore.Mvc.Versioning.Conventions;
using Microsoft.Extensions.DependencyInjection;

namespace KeiroGenesis.API.Core.Versioning
{
    /// <summary>
    /// API Versioning Strategy for KeiroGenesis
    /// 
    /// We use URL Path versioning as primary method:
    /// - /api/v1/clone
    /// - /api/v2/clone
    /// 
    /// With Header versioning as secondary:
    /// - X-API-Version: 1.0
    /// - X-API-Version: 2.0
    /// 
    /// Versioning Rules:
    /// - v1: Initial stable release (current)
    /// - v2: Breaking changes only
    /// - v3: Major architectural changes
    /// 
    /// Deprecation Policy:
    /// - 6 months notice before deprecation
    /// - 12 months support after new version
    /// - Clear migration guides provided
    /// </summary>
    public static class ApiVersioningConfiguration
    {
        public const string V1 = "1.0";
        public const string V2 = "2.0";
        public const string V3 = "3.0";

        public const string CurrentVersion = V1;
        public const string DeprecatedVersion = "";  // None yet

        public static void ConfigureApiVersioning(this IServiceCollection services)
        {
            services.AddApiVersioning(options =>
            {
                // Specify the default API version
                options.DefaultApiVersion = new ApiVersion(1, 0);

                // Assume default version when not specified
                options.AssumeDefaultVersionWhenUnspecified = true;

                // Report API versions in response headers
                options.ReportApiVersions = true;

                // Configure how to read the API version
                options.ApiVersionReader = ApiVersionReader.Combine(
                    // 1. URL Path segment versioning (primary)
                    new UrlSegmentApiVersionReader(),

                    // 2. Header versioning (secondary)
                    new HeaderApiVersionReader("X-API-Version"),

                    // 3. Query string versioning (fallback)
                    new QueryStringApiVersionReader("api-version"),

                    // 4. Media type versioning (for advanced users)
                    new Microsoft.AspNetCore.Mvc.Versioning.MediaTypeApiVersionReader("version")
                );
            });
            
        }
    }

    /// <summary>
    /// Custom API version conventions
    /// </summary>
    public class ApiVersionConvention : IControllerConvention
    {
        public void Apply(IControllerConventionBuilder controller)
        {
            // Apply versioning rules based on controller namespace
            var controllerNamespace = controller.ControllerType.Namespace;

            if (controllerNamespace?.Contains(".V1.") == true)
            {
                controller.HasApiVersion(new ApiVersion(1, 0));
            }
            else if (controllerNamespace?.Contains(".V2.") == true)
            {
                controller.HasApiVersion(new ApiVersion(2, 0));
            }
            else
            {
                // Default to v1 for unversioned controllers
                controller.HasApiVersion(new ApiVersion(1, 0));
            }
        }

        public bool Apply(IControllerConventionBuilder builder, ControllerModel controller)
        {
            throw new NotImplementedException();
        }
    }
}
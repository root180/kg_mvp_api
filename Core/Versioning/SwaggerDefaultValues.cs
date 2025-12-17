// File: KeiroGenesis.API/Core/Versioning/SwaggerDefaultValues.cs
// Purpose: Operation filter to integrate Swagger with API versioning

using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.OpenApi.Any;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System;
using System.Linq;
using System.Text.Json;

namespace KeiroGenesis.API.Core.Versioning
{
    /// <summary>
    /// Configures Swagger operations to work properly with API versioning.
    /// Works in conjunction with ApiVersioningConfiguration to ensure
    /// Swagger UI correctly displays versioned endpoints.
    /// </summary>
    public class SwaggerDefaultValues : IOperationFilter
    {
        /// <summary>
        /// Applies the filter to the Swagger operation.
        /// Handles default values, deprecation status, and parameter requirements.
        /// </summary>
        /// <param name="operation">The operation being documented</param>
        /// <param name="context">The operation filter context</param>
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            var apiDescription = context.ApiDescription;

            // Set operation ID if not already specified
            operation.OperationId ??= apiDescription.GroupName;

            // Handle deprecated API versions
            if (apiDescription.IsDeprecated())
            {
                operation.Deprecated = true;

                // Add deprecation notice to description
                var deprecationNotice = "**This API version is deprecated. Please migrate to a newer version.**\n\n";
                operation.Description = deprecationNotice + (operation.Description ?? string.Empty);
            }

            // Process parameters if they exist
            if (operation.Parameters == null)
            {
                return;
            }

            foreach (var parameter in operation.Parameters)
            {
                var description = apiDescription.ParameterDescriptions
                    .FirstOrDefault(p => p.Name == parameter.Name);

                if (description == null)
                {
                    continue;
                }

                // Set parameter description from model metadata
                parameter.Description ??= description.ModelMetadata?.Description;

                // Handle default values
                if (parameter.Schema.Default == null &&
                    description.DefaultValue != null &&
                    description.DefaultValue.GetType() != typeof(DBNull))
                {
                    try
                    {
                        // Serialize the default value to JSON
                        var json = JsonSerializer.Serialize(
                            description.DefaultValue,
                            description.ModelMetadata?.ModelType ?? description.DefaultValue.GetType());

                        parameter.Schema.Default = OpenApiAnyFactory.CreateFromJson(json);
                    }
                    catch
                    {
                        // Fallback to string representation if JSON serialization fails
                        parameter.Schema.Default = new OpenApiString(description.DefaultValue.ToString());
                    }
                }

                // Mark required parameters
                parameter.Required |= description.IsRequired;

                // Add example values for common parameter names
                if (parameter.Schema.Example == null)
                {
                    parameter.Schema.Example = GetExampleValue(parameter.Name, parameter.Schema.Type);
                }
            }
        }

        /// <summary>
        /// Provides example values for common parameter names
        /// </summary>
        private static IOpenApiAny? GetExampleValue(string parameterName, string? schemaType)
        {
            // Provide sensible examples based on parameter name
            var lowerName = parameterName.ToLowerInvariant();

            return lowerName switch
            {
                "id" or "userid" or "tenantid" => new OpenApiString(Guid.NewGuid().ToString()),
                "email" => new OpenApiString("user@example.com"),
                "username" => new OpenApiString("john_doe"),
                "password" => new OpenApiString("SecurePassword123!"),
                "firstname" => new OpenApiString("John"),
                "lastname" => new OpenApiString("Doe"),
                "page" or "pagenumber" => new OpenApiInteger(1),
                "pagesize" or "limit" => new OpenApiInteger(10),
                "search" or "query" => new OpenApiString("search term"),
                "sort" or "orderby" => new OpenApiString("name"),
                "api-version" => new OpenApiString(ApiVersioningConfiguration.CurrentVersion),
                _ => null
            };
        }
    }

    /// <summary>
    /// Extension methods for API description
    /// </summary>
    public static class ApiDescriptionExtensions
    {
        /// <summary>
        /// Determines if an API is deprecated based on metadata or version
        /// </summary>
        public static bool IsDeprecated(this ApiDescription apiDescription)
        {
            // Check for Obsolete attribute
            var hasObsoleteAttribute = apiDescription.ActionDescriptor.EndpointMetadata
                .OfType<ObsoleteAttribute>()
                .Any();

            if (hasObsoleteAttribute)
            {
                return true;
            }

            // Check if version is marked as deprecated in configuration
            var version = apiDescription.GroupName;
            if (!string.IsNullOrEmpty(ApiVersioningConfiguration.DeprecatedVersion) &&
                version == ApiVersioningConfiguration.DeprecatedVersion)
            {
                return true;
            }

            return false;
        }
    }
}
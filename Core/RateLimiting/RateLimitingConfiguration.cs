// File: KeiroGenesis.API/API/RateLimiting/RateLimitingConfiguration.cs
// Location: API/RateLimiting folder

using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using System.Security.Claims;
using System.Net;

namespace KeiroGenesis.API.Core.RateLimiting
{
    /// <summary>
    /// Rate Limiting Configuration for KeiroGenesis API
    /// Implements various rate limiting strategies to prevent abuse
    /// For .NET 8.0 - uses built-in rate limiting (no separate package needed)
    /// </summary>
    public static class RateLimitingConfiguration
    {
        public const string FixedWindowPolicy = "fixed";
        public const string SlidingWindowPolicy = "sliding";
        public const string TokenBucketPolicy = "token";
        public const string ConcurrencyPolicy = "concurrency";
        public const string ChainedPolicy = "chained";
        public const string CustomPolicy = "custom";

        /// <summary>
        /// Configure rate limiting middleware and policies
        /// </summary>
        public static void ConfigureRateLimiting(this IServiceCollection services)
        {
            services.AddRateLimiter(options =>
            {
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
                    httpContext => RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: GetPartitionKey(httpContext),
                        factory: partition => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = 100,
                            Window = TimeSpan.FromMinutes(1)
                        }));

                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

                // Fixed Window Rate Limiter
                options.AddFixedWindowLimiter(FixedWindowPolicy, limiterOptions =>
                {
                    limiterOptions.AutoReplenishment = true;
                    limiterOptions.PermitLimit = 60;
                    limiterOptions.Window = TimeSpan.FromMinutes(1);
                    limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                    limiterOptions.QueueLimit = 10;
                });

                // Sliding Window Rate Limiter
                options.AddSlidingWindowLimiter(SlidingWindowPolicy, limiterOptions =>
                {
                    limiterOptions.AutoReplenishment = true;
                    limiterOptions.PermitLimit = 100;
                    limiterOptions.Window = TimeSpan.FromMinutes(1);
                    limiterOptions.SegmentsPerWindow = 4;
                    limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                    limiterOptions.QueueLimit = 10;
                });

                // Token Bucket Rate Limiter
                options.AddTokenBucketLimiter(TokenBucketPolicy, limiterOptions =>
                {
                    limiterOptions.AutoReplenishment = true;
                    limiterOptions.TokenLimit = 100;
                    limiterOptions.TokensPerPeriod = 20;
                    limiterOptions.ReplenishmentPeriod = TimeSpan.FromSeconds(10);
                    limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                    limiterOptions.QueueLimit = 10;
                });

                // Concurrency Limiter
                options.AddConcurrencyLimiter(ConcurrencyPolicy, limiterOptions =>
                {
                    limiterOptions.PermitLimit = 10;
                    limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                    limiterOptions.QueueLimit = 5;
                });

                // Chained Policy (combines multiple policies)
                options.AddPolicy(ChainedPolicy, httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: GetPartitionKey(httpContext),
                        factory: partition => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = 30,
                            Window = TimeSpan.FromMinutes(1)
                        }));

                // Custom Policy with different limits per user type
                options.AddPolicy(CustomPolicy, httpContext =>
                {
                    var user = httpContext.User;
                    if (user.IsInRole("Premium"))
                    {
                        return RateLimitPartition.GetNoLimiter(GetPartitionKey(httpContext));
                    }
                    else if (user.IsInRole("Basic"))
                    {
                        return RateLimitPartition.GetTokenBucketLimiter(
                            partitionKey: GetPartitionKey(httpContext),
                            factory: partition => new TokenBucketRateLimiterOptions
                            {
                                AutoReplenishment = true,
                                TokenLimit = 50,
                                TokensPerPeriod = 10,
                                ReplenishmentPeriod = TimeSpan.FromSeconds(10)
                            });
                    }
                    else
                    {
                        return RateLimitPartition.GetFixedWindowLimiter(
                            partitionKey: GetPartitionKey(httpContext),
                            factory: partition => new FixedWindowRateLimiterOptions
                            {
                                AutoReplenishment = true,
                                PermitLimit = 10,
                                Window = TimeSpan.FromMinutes(1)
                            });
                    }
                });

                options.OnRejected = async (context, token) =>
                {
                    context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    {
                        await context.HttpContext.Response.WriteAsync(
                            $"Too many requests. Please retry after {retryAfter.TotalSeconds} second(s).",
                            cancellationToken: token);
                    }
                    else
                    {
                        await context.HttpContext.Response.WriteAsync(
                            "Too many requests. Please retry later.",
                            cancellationToken: token);
                    }
                };
            });
        }

        private static string GetPartitionKey(HttpContext httpContext)
        {
            // Use authenticated user ID if available
            if (httpContext.User?.Identity?.IsAuthenticated == true)
            {
                return httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous";
            }

            // Fall back to IP address for anonymous users
            var ipAddress = httpContext.Connection.RemoteIpAddress;
            if (ipAddress != null)
            {
                // Handle IPv6 localhost
                if (IPAddress.IsLoopback(ipAddress))
                {
                    return "localhost";
                }
                return ipAddress.ToString();
            }

            return "unknown";
        }
    }
}
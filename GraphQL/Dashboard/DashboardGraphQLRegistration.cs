using HotChocolate.Execution.Configuration;

namespace KeiroGenesis.API.GraphQL.Dashboard
{
    public static class DashboardGraphQLRegistration
    {
        public static IServiceCollection AddDashboardGraphQL(this IServiceCollection services)
        {
            services.AddScoped<IPersonalDashboardGraphQLRepository, PersonalDashboardGraphQLRepository>();
            services.AddScoped<DashboardGraphQLService>();
            return services;
        }

        public static IRequestExecutorBuilder AddDashboardGraphQLServer(this IServiceCollection services)
        {
            return services
                .AddGraphQLServer()
                .AddAuthorization()
                .AddQueryType<DashboardQuery>();
        }
    }

}


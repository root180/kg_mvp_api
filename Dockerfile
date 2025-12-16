# ============================================================
# File: Dockerfile
# Purpose: Build and run KeiroGenesis API (.NET 8) for Docker
#          Standardized on port 8080 for local and Cloud Run
# ============================================================

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY ["KeiroGenesis.API.csproj", "./"]
RUN dotnet restore "KeiroGenesis.API.csproj"

# Copy everything else and build
COPY . .
RUN dotnet publish "KeiroGenesis.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# ------------------------------------------------------------
# 🔖 Embed build metadata (Git SHA + UTC timestamp for Swagger)
# ------------------------------------------------------------
ARG GIT_SHA
ARG BUILD_TIME
RUN echo "KeiroGenesis Build SHA: ${GIT_SHA}" > /app/publish/version.txt && \
    echo "Build Time (UTC): ${BUILD_TIME}" >> /app/publish/version.txt


# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy published files
COPY --from=build /app/publish .

# Expose port 8080 (standardized for local and Cloud Run)
EXPOSE 8080

# Configure ASP.NET Core to listen on port 8080
ENV ASPNETCORE_URLS=http://+:8080

# Default to Production (can be overridden by docker-compose)
ENV ASPNETCORE_ENVIRONMENT=Production

# Health check on port 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Start the application
ENTRYPOINT ["dotnet", "KeiroGenesis.API.dll"]

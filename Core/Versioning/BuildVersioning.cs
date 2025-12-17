// File: KeiroGenesis.API/API/Versioning/BuildVersioning.cs
// Location: Create folders API/Versioning in your API project

using System.Reflection;

namespace KeiroGenesis.API.Core.Versioning
{
    public class BuildInfo
    {
        public string Version { get; set; } = "1.0.0";
        public string BuildNumber { get; set; } = "0";
        public string BuildDate { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd");
        public string Environment { get; set; } = "Development";
        public string GitCommit { get; set; } = "local";
        public string GitBranch { get; set; } = "main";

        public string FullVersionString => $"{Version}.{BuildNumber}";
        public string DisplayName => $"KeiroGenesis.API ({Environment} {BuildNumber}-{BuildDate:yyMMdd})";
    }

    public interface IBuildInfoService
    {
        BuildInfo GetBuildInfo();
        string GetDisplayName();
    }

    public class BuildInfoService : IBuildInfoService
    {
        private readonly BuildInfo _buildInfo;
        private readonly IWebHostEnvironment _environment;

        public BuildInfoService(IConfiguration configuration, IWebHostEnvironment environment)
        {
            _environment = environment;
            _buildInfo = new BuildInfo
            {
                Version = configuration["BuildInfo:Version"] ?? GetAssemblyVersion(),
                BuildNumber = configuration["BuildInfo:BuildNumber"] ?? GetAutoBuildNumber(),
                BuildDate = configuration["BuildInfo:BuildDate"] ?? DateTime.UtcNow.ToString("yyyy-MM-dd"),
                Environment = GetEnvironmentName(),
                GitCommit = configuration["BuildInfo:GitCommit"] ?? "local",
                GitBranch = configuration["BuildInfo:GitBranch"] ?? "main"
            };
        }

        public BuildInfo GetBuildInfo() => _buildInfo;

        public string GetDisplayName() => _buildInfo.DisplayName;

        private string GetAssemblyVersion()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            return $"{version?.Major}.{version?.Minor}.{version?.Build}";
        }

        private string GetAutoBuildNumber()
        {
            // Format: YYDDD-HHMM (Year, Day of Year, Hour, Minute)
            var now = DateTime.UtcNow;
            var yearDay = $"{now:yy}{now.DayOfYear:D3}";
            var time = $"{now:HHmm}";
            return $"{yearDay}-{time}";
        }

        private string GetEnvironmentName()
        {
            return _environment.EnvironmentName switch
            {
                "Development" => "Dev",
                "Test" => "Test",
                "Production" => "Prod",
                _ => _environment.EnvironmentName
            };
        }
    }
}
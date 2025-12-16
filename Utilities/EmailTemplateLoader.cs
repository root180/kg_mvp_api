using System.Text;
using Path = System.IO.Path;

namespace KeiroGenesis.API.Utilities
{
    public static class EmailTemplateLoader
    {
        // If you inject IWebHostEnvironment, you can replace this with env.ContentRootPath
        private static string ContentRoot =>
            AppContext.BaseDirectory; // bin/<config>/netX/

        private static string TemplatesRoot =>
            System.IO.Path.Combine(ContentRoot, "Templates");

        private static string EmailsRoot =>
            Path.Combine(TemplatesRoot, "Emails");

        private static string LayoutsRoot =>
            Path.Combine(EmailsRoot, "Layouts");

        // ---- PUBLIC API ------------------------------------------------------

        // Load a single template file by name from a subfolder
        public static string LoadTemplate(string relativePath)
        {
            var path = System.IO.Path.Combine(TemplatesRoot, relativePath);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Email template not found: {path}");
            return File.ReadAllText(path, Encoding.UTF8);
        }

        // Simple token replacement: {{token}}
        public static string ReplaceTokens(string html, IDictionary<string, string> tokens)
        {
            if (tokens == null) return html;
            foreach (var kvp in tokens)
            {
                html = html.Replace($"{{{kvp.Key}}}", kvp.Value ?? string.Empty, StringComparison.Ordinal);
            }
            return html;
        }

        /// <summary>
        /// Renders a full email by injecting header/footer/body into the base layout,
        /// then replacing {{tokens}} across the entire document.
        /// </summary>
        /// <param name="subject">Used in the &lt;title&gt; of the layout.</param>
        /// <param name="contentTemplateFileName">e.g., "mfa_code.html", "verify_email.html"</param>
        /// <param name="tokens">Dictionary of token -> value (e.g., code, expires_minutes)</param>
        public static string Render(string subject, string contentTemplateFileName, IDictionary<string, string> tokens)
        {
            // Your structure per screenshot:
            // Templates/
            //   Emails/
            //     mfa_code.html
            //     verify_email.html
            //     password_reset.html
            //     welcome.html
            //     Layouts/
            //       baser.html
            //       header.html
            //       footer.html

            var baseLayout = LoadFromLayouts("baser.html");   // note: “baser.html” in your repo
            var header = LoadFromLayouts("header.html");
            var footer = LoadFromLayouts("footer.html");
            var body = LoadFromEmails(contentTemplateFileName);

            // Inject regions into base layout
            var html = baseLayout
                .Replace("{{subject}}", subject ?? string.Empty, StringComparison.Ordinal)
                .Replace("{{header}}", header, StringComparison.Ordinal)
                .Replace("{{footer}}", footer, StringComparison.Ordinal)
                .Replace("{{body}}", body, StringComparison.Ordinal);

            // Replace tokens everywhere
            html = ReplaceTokens(html, tokens);

            return html;
        }

        // ---- PRIVATE HELPERS -------------------------------------------------

        private static string LoadFromLayouts(string fileName)
        {
            var path = Path.Combine(LayoutsRoot, fileName);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Layout template not found: {path}");
            return File.ReadAllText(path, Encoding.UTF8);
        }

        private static string LoadFromEmails(string fileName)
        {
            var path = Path.Combine(EmailsRoot, fileName);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Email content template not found: {path}");
            return File.ReadAllText(path, Encoding.UTF8);
        }
    }
}

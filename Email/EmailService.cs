using KeiroGenesis.API.Utilities;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace KeiroGenesis.API.Services
{
    /// <summary>
    /// Concrete SendGrid-backed email provider for KeiroClone/KeiroGenesis.
    /// Handles all verification and MFA emails using a unified HTML template.
    /// </summary>
    /// 
    public interface IEmailProvider
    { // ======================================================
        // 📨 Generic base sender (used internally by all flows)
        // ======================================================
        Task<bool> SendEmailAsync(string to, string subject, string bodyPlain, string bodyHtml = null);

        // ======================================================
        // 🔐 Password Recovery & Security (⭐ MISSING IN YOUR VERSION)
        // ======================================================
        Task<bool> SendPasswordResetEmailAsync(string email, string userName, string resetLink);
        Task<bool> SendForgotUsernameEmailAsync(string email, string userName);
        Task<bool> SendPasswordChangedNotificationAsync(string email, string userName);

        // ======================================================
        // 🧱 Unified KeiroClone Verification Flows (HTML template)
        // ======================================================
        /// <summary>
        /// Sends the KeiroClone MFA verification email using the master HTML layout.
        /// </summary>
        Task<bool> SendMfaVerificationEmailAsync(string email, string code, string userName);

        /// <summary>
        /// Sends the initial KeiroClone registration verification email.
        /// </summary>
        Task<bool> SendRegisterVerificationEmailAsync(string email, string code, string userName);

        /// <summary>
        /// Sends the KeiroClone resend verification email using the same master template.
        /// </summary>
        Task<bool> ResendVerificationEmailAsync(string email, string code, string userName);

        // ======================================================
        // 🎉 Welcome & Onboarding (⭐ MISSING IN YOUR VERSION)
        // ======================================================
        Task<bool> SendWelcomeEmailAsync(string email, string userName);

        // ======================================================
        // 🔒 Backward-compatible aliases
        // ======================================================
        Task<bool> SendMfaSetupCodeAsync(string toEmail, string code);
        Task<bool> SendVerificationEmailAsync(string email, string code, string userName);
        Task<bool> SendVerificationEmailAsync(string toEmail, string verificationLink);


    }
    public class EmailService : IEmailProvider
    {
        private readonly SendGridClient _client;
        private readonly string _fromAddress;
        private readonly string _fromName;
        private readonly string _replyToAddress;
        private readonly IConfiguration _config;
        private readonly ILogger<EmailService> _logger;

        // ✅ Inject both IConfiguration and ILogger
        public EmailService(IConfiguration config, ILogger<EmailService> logger)
        {
            _config = config;
            _logger = logger;

            var apiKey = config["Email:SendGridApiKey"] ?? Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException("SendGrid API key is missing.");

            _client = new SendGridClient(apiKey);
            _fromAddress = config["Email:FromAddress"] ?? "no-reply@keiroclone.com";
            _fromName = config["Email:FromName"] ?? "KeiroClone Security";
            _replyToAddress = config["Email:ReplyTo"] ?? "support@keiroclone.com";
        }

        // ✅ Generic Send used by all other methods
        public async Task<bool> SendEmailAsync(string toEmail, string subject, string bodyPlain, string bodyHtml = null)
        {
            try
            {
                var from = new EmailAddress(_fromAddress, _fromName);
                var to = new EmailAddress(toEmail);
                var msg = MailHelper.CreateSingleEmail(from, to, subject, bodyPlain, bodyHtml ?? bodyPlain);
                msg.ReplyTo = new EmailAddress(_replyToAddress, "KeiroClone Support");

                var response = await _client.SendEmailAsync(msg);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("✅ Email sent successfully to {Email} (Subject: {Subject})", toEmail, subject);
                    return true;
                }

                var err = await response.Body.ReadAsStringAsync();
                _logger.LogError("❌ SendGrid error {Status}: {Error}", response.StatusCode, err);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Exception while sending email to {Email}", toEmail);
                return false;
            }
        }

        // ✅ MFA setup (initial enrollment, non-template)
        public async Task<bool> SendMfaSetupCodeAsync(string toEmail, string code)
        {
            var subject = "Your KeiroClone Security Code";
            var bodyPlain = $"Your KeiroClone verification code is {code}. This code expires in 10 minutes.";
            var bodyHtml = $@"
                <div style='font-family:Helvetica,Arial,sans-serif;font-size:15px;color:#333;'>
                    <p>Hello,</p>
                    <p>Your KeiroClone verification code is:</p>
                    <h2 style='background:#1877f2;color:#fff;display:inline-block;padding:10px 20px;border-radius:6px;'>{code}</h2>
                    <p style='margin-top:10px;'>This code will expire in 10 minutes.</p>
                    <p>If you didn’t request this, please secure your account immediately.</p>
                    <br/>
                    <strong>- KeiroClone Security Team</strong><br/>
                    <span style='font-size:12px;color:#888;'>© {DateTime.UtcNow.Year} KeiroLegacy Inc. All rights reserved.</span>
                </div>";

            return await SendEmailAsync(toEmail, subject, bodyPlain, bodyHtml);
        }

        // ============================================================
        // Unified KeiroClone Verification Email System (HTML Template)
        // ============================================================

        private async Task<bool> SendVerificationEmailAsync(
            string recipientEmail,
            string code,
            string userName,
            string purposeText,
            string subject)
        {
            try
            {
                var firstName = userName?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                         .FirstOrDefault() ?? "there";

                var htmlBody = EmailTemplateLoader.Render(subject, "email-template-verification-code.html",
                    new Dictionary<string, string>
                    {
                        { "USER_NAME", userName ?? "there" },
                        { "USER_FIRST_NAME", firstName },
                        { "VERIFICATION_CODE", code },
                        { "USER_EMAIL", recipientEmail },
                        { "PURPOSE_TEXT", purposeText },
                        { "YEAR", DateTime.UtcNow.Year.ToString() }
                    });

                var textBody = $"Hi {firstName}, your KeiroClone verification code is {code}. It expires in 10 minutes.";

                var sent = await SendEmailAsync(recipientEmail, subject, textBody, htmlBody);
                if (!sent)
                    _logger.LogWarning("⚠️ Verification email ({Purpose}) failed to send to {Email}", purposeText, recipientEmail);

                return sent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send verification email ({Purpose}) to {Email}", purposeText, recipientEmail);
                return false;
            }
        }

        // ------------------------------------------------------------
        // 1️⃣  MFA LOGIN VERIFICATION EMAIL
        // ------------------------------------------------------------
        public async Task<bool> SendMfaVerificationEmailAsync(string email, string code, string userName)
        {
            return await SendVerificationEmailAsync(
                email,
                code,
                userName,
                "Use this code to complete your sign-in",
                "KeiroClone MFA Verification Code");
        }

        // ------------------------------------------------------------
        // 2️⃣  REGISTRATION VERIFICATION EMAIL
        // ------------------------------------------------------------
        public async Task<bool> SendRegisterVerificationEmailAsync(string email, string code, string userName)
        {
            return await SendVerificationEmailAsync(
                email,
                code,
                userName,
                "One more step to sign up",
                "Verify Your KeiroClone Account");
        }

        // ------------------------------------------------------------
        // 3️⃣  RESEND VERIFICATION EMAIL
        // ------------------------------------------------------------
        public async Task<bool> ResendVerificationEmailAsync(string email, string code, string userName)
        {
            return await SendVerificationEmailAsync(
                email,
                code,
                userName,
                "Here’s your new verification code",
                "Your KeiroClone Verification Code (Resent)");
        }


        public async Task<bool> SendVerificationEmailAsync(string email, string code, string userName)
        {
            // Backward-compatible wrapper → use Registration flow
            return await SendRegisterVerificationEmailAsync(email, code, userName);
        }

        // ✅ Overload for link-based verification (registration confirmation, password reset, etc.)
        public async Task<bool> SendVerificationEmailAsync(string toEmail, string verificationLink)
        {
            var subject = "Verify your KeiroClone account";

            var htmlBody = $@"
        <div style='font-family:Helvetica,Arial,sans-serif;font-size:15px;color:#333;'>
            <p>Hello,</p>
            <p>Please confirm your KeiroClone account by clicking the link below:</p>
            <p><a href='{verificationLink}' style='color:#1877f2;'>{verificationLink}</a></p>
            <p>This link will expire in 24 hours.</p>
            <br/>
            <strong>- KeiroClone Security Team</strong><br/>
            <span style='font-size:12px;color:#888;'>© {DateTime.UtcNow.Year} KeiroLegacy Inc. All rights reserved.</span>
        </div>";

            var textBody = $"Confirm your KeiroClone account: {verificationLink}";

            return await SendEmailAsync(toEmail, subject, textBody, htmlBody);
        }

        // ------------------------------------------------------------
        // 4️⃣  PASSWORD CHANGED NOTIFICATION EMAIL
        // ------------------------------------------------------------
        public async Task<bool> SendPasswordChangedNotificationAsync(string email, string userName)
        {
            try
            {
                var firstName = userName?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                         .FirstOrDefault() ?? "there";

                var htmlBody = EmailTemplateLoader.Render(
                    "Your KeiroClone Password Was Changed",
                    "email-template-password-changed.html",
                    new Dictionary<string, string>
                    {
                { "USER_NAME", userName ?? "there" },
                { "USER_FIRST_NAME", firstName },
                { "USER_EMAIL", email },
                { "CHANGE_DATE", DateTime.UtcNow.ToString("MMMM dd, yyyy") },
                { "CHANGE_TIME", DateTime.UtcNow.ToString("hh:mm tt") + " UTC" },
                { "YEAR", DateTime.UtcNow.Year.ToString() }
                    });

                var textBody = $"Hi {firstName}, your KeiroClone password was changed on {DateTime.UtcNow:MMMM dd, yyyy}. If you didn't make this change, please contact support immediately.";

                var sent = await SendEmailAsync(email, "Your KeiroClone Password Was Changed", textBody, htmlBody);

                if (!sent)
                    _logger.LogWarning("⚠️ Password changed notification failed to send to {Email}", email);

                return sent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send password changed notification to {Email}", email);
                return false;
            }
        }
        public async Task<bool> SendWelcomeEmailAsync(string email, string userName)
        {
            try
            {
                var firstName = userName?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                         .FirstOrDefault() ?? "there";

                var htmlBody = EmailTemplateLoader.Render(
                    "Welcome to KeiroClone",
                    "welcome.html",
                    new Dictionary<string, string>
                    {
                { "USER_NAME", userName ?? "there" },
                { "USER_FIRST_NAME", firstName },
                { "USER_EMAIL", email },
                { "YEAR", DateTime.UtcNow.Year.ToString() }
                    });

                var textBody = $"Welcome to KeiroClone, {firstName}! Your account has been successfully created.";

                return await SendEmailAsync(
                    email,
                    "Welcome to KeiroClone",
                    textBody,
                    htmlBody
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send welcome email to {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendPasswordResetEmailAsync(
    string email,
    string userName,
    string resetLink)
        {
            try
            {
                var firstName = userName?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                         .FirstOrDefault() ?? "there";

                var htmlBody = EmailTemplateLoader.Render(
                    "Reset Your KeiroClone Password",
                    "password_reset.html",
                    new Dictionary<string, string>
                    {
                { "USER_NAME", userName ?? "there" },
                { "USER_FIRST_NAME", firstName },
                { "RESET_LINK", resetLink },
                { "USER_EMAIL", email },
                { "YEAR", DateTime.UtcNow.Year.ToString() }
                    });

                var textBody =
                    $"Hi {firstName}, reset your KeiroClone password using this link: {resetLink}";

                return await SendEmailAsync(
                    email,
                    "Reset Your KeiroClone Password",
                    textBody,
                    htmlBody
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send password reset email to {Email}", email);
                return false;
            }
        }
        public async Task<bool> SendForgotUsernameEmailAsync(
    string email,
    string userName)
        {
            try
            {
                var firstName = userName?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                         .FirstOrDefault() ?? "there";

                var htmlBody = EmailTemplateLoader.Render(
                    "Your KeiroClone Username",
                    "verify_email.html",
                    new Dictionary<string, string>
                    {
                { "USER_NAME", userName },
                { "USER_FIRST_NAME", firstName },
                { "USER_EMAIL", email },
                { "PURPOSE_TEXT", "You requested your KeiroClone username" },
                { "YEAR", DateTime.UtcNow.Year.ToString() }
                    });

                var textBody =
                    $"Hi {firstName}, your KeiroClone username is: {userName}";

                return await SendEmailAsync(
                    email,
                    "Your KeiroClone Username",
                    textBody,
                    htmlBody
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send forgot-username email to {Email}", email);
                return false;
            }
        }


    }
}

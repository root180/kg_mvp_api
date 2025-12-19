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

        Task<bool> SendEmailVerificationAsync(string toEmail, string username, string verificationCode);
        Task<bool> SendEmailChangeNotificationAsync(string toEmail, string username, string newEmail);

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

            var apiKey = config["Email:SENDGRID_API_KEY"] ?? Environment.GetEnvironmentVariable("SENDGRID_API_KEY");

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

        // ============================================================
        // EMAIL UPDATE FEATURE - Verification Code
        // ============================================================

        public async Task<bool> SendEmailVerificationAsync(
            string toEmail,
            string username,
            string verificationCode)
        {
            try
            {
                var subject = "Verify Your New Email Address";

                var plainTextBody = $@"
Hello {username},

You recently requested to change your email address. To complete this change, please use the verification code below:

Verification Code: {verificationCode}

This code will expire in 24 hours.

If you did not request this change, please ignore this email and your email address will remain unchanged.

Best regards,
KeiroClone Security Team
";

                var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
        .content {{ background-color: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }}
        .code-box {{ 
            background-color: #fff; 
            border: 2px dashed #4F46E5; 
            padding: 20px; 
            text-align: center; 
            font-size: 32px; 
            font-weight: bold; 
            letter-spacing: 5px; 
            margin: 20px 0; 
            border-radius: 5px;
        }}
        .warning {{ background-color: #FEF3C7; padding: 15px; border-left: 4px solid #F59E0B; margin: 20px 0; }}
        .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>✉️ Verify Your New Email</h1>
        </div>
        <div class='content'>
            <p>Hello <strong>{username}</strong>,</p>
            
            <p>You recently requested to change your email address. To complete this change, please use the verification code below:</p>
            
            <div class='code-box'>
                {verificationCode}
            </div>
            
            <p>This code will expire in <strong>24 hours</strong>.</p>
            
            <div class='warning'>
                <strong>⚠️ Security Notice:</strong> If you did not request this change, please ignore this email. Your email address will remain unchanged.
            </div>
            
            <p>For your security, never share this code with anyone.</p>
            
            <p>Best regards,<br>
            <strong>KeiroClone Security Team</strong></p>
        </div>
        <div class='footer'>
            <p>This is an automated message. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
";

                return await SendEmailAsync(toEmail, subject, plainTextBody, htmlBody);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email verification to {Email}", toEmail);
                return false;
            }
        }

        // ============================================================
        // EMAIL UPDATE FEATURE - Change Notification
        // ============================================================

        public async Task<bool> SendEmailChangeNotificationAsync(
            string toEmail,
            string username,
            string newEmail)
        {
            try
            {
                var subject = "⚠️ Email Address Change Request";

                var plainTextBody = $@"
Hello {username},

We're writing to inform you that a request has been made to change the email address associated with your KeiroClone account.

Current Email: {toEmail}
New Email: {newEmail}

If you made this request, no further action is needed. The new email address must be verified before the change takes effect.

If you DID NOT make this request, your account may be compromised. Please:
1. Change your password immediately
2. Contact our support team

Best regards,
KeiroClone Security Team
";

                var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #DC2626; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
        .content {{ background-color: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }}
        .info-box {{ background-color: #fff; padding: 15px; border: 1px solid #ddd; margin: 20px 0; border-radius: 5px; }}
        .alert {{ background-color: #FEE2E2; padding: 15px; border-left: 4px solid #DC2626; margin: 20px 0; }}
        .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
        strong {{ color: #DC2626; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>⚠️ Email Change Request</h1>
        </div>
        <div class='content'>
            <p>Hello <strong>{username}</strong>,</p>
            
            <p>We're writing to inform you that a request has been made to change the email address associated with your KeiroClone account.</p>
            
            <div class='info-box'>
                <p><strong>Current Email:</strong> {toEmail}</p>
                <p><strong>New Email:</strong> {newEmail}</p>
            </div>
            
            <p>If you made this request, <strong>no further action is needed</strong>. The new email address must be verified before the change takes effect.</p>
            
            <div class='alert'>
                <p><strong>⚠️ SECURITY ALERT</strong></p>
                <p>If you <strong>DID NOT</strong> make this request, your account may be compromised. Please take the following steps immediately:</p>
                <ol>
                    <li>Change your password</li>
                    <li>Review your account activity</li>
                    <li>Contact our support team</li>
                </ol>
            </div>
            
            <p>Best regards,<br>
            <strong>KeiroClone Security Team</strong></p>
        </div>
        <div class='footer'>
            <p>This is an automated security notification. Please do not reply to this email.</p>
            <p>If you need assistance, contact: support@keiroclone.com</p>
        </div>
    </div>
</body>
</html>
";

                return await SendEmailAsync(toEmail, subject, plainTextBody, htmlBody);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email change notification to {Email}", toEmail);
                return false;
            }
        }


    }
}

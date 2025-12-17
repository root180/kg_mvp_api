using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace KeiroGenesis.API.Helpers
{
    public static class TokenClaimHelper
    {
        // Purpose: Safely extract TenantId and UserId from an authenticated ClaimsPrincipal.
        // Function: Returns valid Guid values or Guid.Empty if missing.
        public static (Guid TenantId, Guid UserId) FromClaimsPrincipal(ClaimsPrincipal user)
        {
            try
            {
                if (user == null || !user.Identity?.IsAuthenticated == true)
                    return (Guid.Empty, Guid.Empty);

                var tenantClaim = user.FindFirst("tenant_id") ?? user.FindFirst("tenantId");
                var userClaim = user.FindFirst(ClaimTypes.NameIdentifier) ??
                                user.FindFirst("sub") ??
                                user.FindFirst("user_id");

                Guid tenantId = Guid.TryParse(tenantClaim?.Value, out var t) ? t : Guid.Empty;
                Guid userId = Guid.TryParse(userClaim?.Value, out var u) ? u : Guid.Empty;

                return (tenantId, userId);
            }
            catch
            {
                // Return empty values instead of throwing, so controllers handle gracefully
                return (Guid.Empty, Guid.Empty);
            }
        }

        // Purpose: Extract TenantId and UserId from a raw JWT string (used for regTokens).
        // Function: Decodes JWT safely without validating signature.
        public static (Guid TenantId, Guid UserId) FromRawToken(string jwt)
        {
            if (string.IsNullOrWhiteSpace(jwt))
                return (Guid.Empty, Guid.Empty);

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(jwt);

                var tenantIdValue = token.Claims.FirstOrDefault(c => c.Type == "tenant_id" || c.Type == "tenantId")?.Value;
                var userIdValue = token.Claims.FirstOrDefault(c => c.Type == "sub" || c.Type == "user_id" || c.Type == "nameid")?.Value;

                Guid tenantId = Guid.TryParse(tenantIdValue, out var t) ? t : Guid.Empty;
                Guid userId = Guid.TryParse(userIdValue, out var u) ? u : Guid.Empty;

                return (tenantId, userId);
            }
            catch
            {
                return (Guid.Empty, Guid.Empty);
            }
        }
    }
}

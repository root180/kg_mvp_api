using System;
using System.Security.Claims;
using KeiroGenesis.API.Helpers;

namespace KeiroGenesis.API.Helpers
{
    public static class ClaimsPrincipalExtensions
    {
        // Purpose: Quick helper to get the tenantId from the authenticated user's claims.
        // Function: Calls the TokenClaimHelper to extract tenantId without needing to repeat logic.
        public static Guid GetTenantId(this ClaimsPrincipal user)
        {
            var (tenantId, _) = TokenClaimHelper.FromClaimsPrincipal(user);
            return tenantId;
        }

        // Purpose: Quick helper to get the userId from the authenticated user's claims.
        // Function: Calls the TokenClaimHelper to extract userId for the current session.
        public static Guid GetUserId(this ClaimsPrincipal user)
        {
            var (_, userId) = TokenClaimHelper.FromClaimsPrincipal(user);
            return userId;
        }
    }
}

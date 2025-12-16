// ==========================================================================
// DAPPER HELPER — Safe Dynamic Object Access
// Core/Helpers/DapperHelper.cs
// ==========================================================================

using System;
using System.Collections.Generic;
using KeyNotFoundException = System.Collections.Generic.KeyNotFoundException;


namespace KeiroGenesis.API.Core.Helpers
{
    public static class DapperHelper
    {
        /// <summary>
        /// Safely get a value from Dapper's dynamic object
        /// </summary>
        public static T GetValue<T>(dynamic obj, string key)
        {
            if (obj == null)
                throw new ArgumentNullException(nameof(obj));

            var dict = (IDictionary<string, object>)obj;

            if (!dict.ContainsKey(key))
                throw new KeyNotFoundException($"Key '{key}' not found in dynamic object");

            var value = dict[key];

            if (value == null)
            {
                if (default(T) != null)
                    throw new InvalidOperationException($"Value for key '{key}' is null but type {typeof(T).Name} is not nullable");
                return default(T)!;
            }

            return (T)value;
        }

        /// <summary>
        /// Safely get a nullable value from Dapper's dynamic object
        /// </summary>
        public static T? GetNullableValue<T>(dynamic obj, string key) where T : struct
        {
            if (obj == null)
                return null;

            var dict = (IDictionary<string, object>)obj;

            if (!dict.ContainsKey(key))
                return null;

            var value = dict[key];
            return value == null ? null : (T)value;
        }

        /// <summary>
        /// Safely get a string value (handles null)
        /// </summary>
        public static string? GetString(dynamic obj, string key)
        {
            if (obj == null)
                return null;

            var dict = (IDictionary<string, object>)obj;

            if (!dict.ContainsKey(key))
                return null;

            return dict[key]?.ToString();
        }

        /// <summary>
        /// Check if key exists
        /// </summary>
        public static bool HasKey(dynamic obj, string key)
        {
            if (obj == null)
                return false;

            var dict = (IDictionary<string, object>)obj;
            return dict.ContainsKey(key);
        }
    }
}
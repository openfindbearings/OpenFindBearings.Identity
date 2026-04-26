using System.Text.Json;

namespace OpenFindBearings.Identity.Extensions
{
    public static class JsonElementExtensions
    {
        public static string[] GetStringArray(this JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                return element.EnumerateArray()
                    .Select(x => x.GetString())
                    .Where(x => x != null)
                    .ToArray()!;
            }

            return Array.Empty<string>();
        }
    }
}

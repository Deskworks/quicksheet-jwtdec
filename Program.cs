using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace QuickSheetJwtDec;

class Program
{
    static void Main(string[] args)
    {
        string? line;
        while ((line = Console.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                string type = root.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";

                if (type == "init" || type == "activate")
                {
                    var resp = new { type = "status", status = "ready" };
                    Console.WriteLine(JsonSerializer.Serialize(resp));
                    Console.Out.Flush();
                }
                else if (type == "request")
                {
                    string token = "";
                    if (root.TryGetProperty("params", out var paramsEl) && paramsEl.ValueKind == JsonValueKind.Array)
                    {
                        var arr = paramsEl.EnumerateArray();
                        if (arr.MoveNext()) token = arr.Current.GetString() ?? "";
                    }
                    else if (root.TryGetProperty("arguments", out var argsEl) && argsEl.ValueKind == JsonValueKind.Array)
                    {
                        var arr = argsEl.EnumerateArray();
                        if (arr.MoveNext()) token = arr.Current.GetString() ?? "";
                    }

                    var cells = DecodeJwt(token.Trim());
                    var response = new { type = "response", cells };
                    Console.WriteLine(JsonSerializer.Serialize(response));
                    Console.Out.Flush();
                }
            }
            catch
            {
                // Ignore malformed messages
            }
        }
    }

    static List<object> DecodeJwt(string token)
    {
        var cells = new List<object>();

        if (string.IsNullOrWhiteSpace(token))
        {
            cells.Add(new { r = 0, c = 0, v = "⚠ No token provided" });
            cells.Add(new { r = 1, c = 0, v = "Usage: jwtdec: eyJhbGciOi..." });
            return cells;
        }

        string[] parts = token.Split('.');
        if (parts.Length < 2)
        {
            cells.Add(new { r = 0, c = 0, v = "⚠ Invalid JWT (expected header.payload[.signature])" });
            return cells;
        }

        // Header row labels
        cells.Add(new { r = 0, c = 0, v = "🔑 JWT DECODE" });
        cells.Add(new { r = 0, c = 1, v = "VALUE" });

        int row = 1;

        // Decode header
        try
        {
            string headerJson = Base64UrlDecode(parts[0]);
            using var headerDoc = JsonDocument.Parse(headerJson);
            cells.Add(new { r = row, c = 0, v = "── HEADER ──" });
            cells.Add(new { r = row, c = 1, v = "" });
            row++;

            foreach (var prop in headerDoc.RootElement.EnumerateObject())
            {
                cells.Add(new { r = row, c = 0, v = prop.Name });
                cells.Add(new { r = row, c = 1, v = FormatValue(prop.Value) });
                row++;
            }
        }
        catch
        {
            cells.Add(new { r = row, c = 0, v = "⚠ Header decode failed" });
            row++;
        }

        // Decode payload
        try
        {
            string payloadJson = Base64UrlDecode(parts[1]);
            using var payloadDoc = JsonDocument.Parse(payloadJson);

            cells.Add(new { r = row, c = 0, v = "── CLAIMS ──" });
            cells.Add(new { r = row, c = 1, v = "" });
            row++;

            foreach (var prop in payloadDoc.RootElement.EnumerateObject())
            {
                string label = prop.Name;
                string value = FormatValue(prop.Value);

                // Annotate well-known claims
                string annotation = GetClaimAnnotation(prop.Name, prop.Value);
                if (!string.IsNullOrEmpty(annotation))
                    value = $"{value}  ({annotation})";

                cells.Add(new { r = row, c = 0, v = label });
                cells.Add(new { r = row, c = 1, v = value });
                row++;
            }
        }
        catch
        {
            cells.Add(new { r = row, c = 0, v = "⚠ Payload decode failed" });
            row++;
        }

        // Signature status
        cells.Add(new { r = row, c = 0, v = "── SIGNATURE ──" });
        if (parts.Length >= 3 && !string.IsNullOrEmpty(parts[2]))
        {
            cells.Add(new { r = row, c = 1, v = $"Present ({parts[2].Length} chars)" });
        }
        else
        {
            cells.Add(new { r = row, c = 1, v = "None (unsecured JWT)" });
        }

        return cells;
    }

    static string Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        byte[] bytes = Convert.FromBase64String(padded);
        return Encoding.UTF8.GetString(bytes);
    }

    static string FormatValue(JsonElement el)
    {
        return el.ValueKind switch
        {
            JsonValueKind.String => el.GetString() ?? "",
            JsonValueKind.Number => el.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            JsonValueKind.Array => $"[{el.GetArrayLength()} items]",
            JsonValueKind.Object => "{...}",
            _ => el.GetRawText()
        };
    }

    static string GetClaimAnnotation(string claim, JsonElement value)
    {
        if ((claim == "exp" || claim == "iat" || claim == "nbf") &&
            value.ValueKind == JsonValueKind.Number &&
            value.TryGetInt64(out long epoch))
        {
            try
            {
                var dt = DateTimeOffset.FromUnixTimeSeconds(epoch);
                string formatted = dt.ToString("yyyy-MM-dd HH:mm:ss UTC");
                if (claim == "exp")
                {
                    var now = DateTimeOffset.UtcNow;
                    if (dt < now)
                        return $"{formatted} ⚠ EXPIRED";
                    else
                    {
                        var remaining = dt - now;
                        if (remaining.TotalHours < 1)
                            return $"{formatted} ⏳ {remaining.Minutes}m left";
                        else if (remaining.TotalDays < 1)
                            return $"{formatted} ⏳ {remaining.Hours}h left";
                        else
                            return $"{formatted} ✓ {remaining.Days}d left";
                    }
                }
                return formatted;
            }
            catch { }
        }

        return claim switch
        {
            "iss" => "issuer",
            "sub" => "subject",
            "aud" => "audience",
            "exp" => "expiration",
            "iat" => "issued at",
            "nbf" => "not before",
            "jti" => "JWT ID",
            "azp" => "authorized party",
            "scope" => "permissions",
            "email_verified" => value.GetRawText() == "true" ? "✓ verified" : "✗ unverified",
            _ => ""
        };
    }
}

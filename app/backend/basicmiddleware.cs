using Microsoft.AspNetCore.Http;
using System;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

public class BasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _username = "apollo"; // Replace with your username
    private readonly string _password = "take1smallstep"; // Replace with your password

    public BasicAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.ContainsKey("Authorization"))
    {
        // If the Authorization header is missing, return a 401 Unauthorized response
        context.Response.Headers["WWW-Authenticate"] = "Basic";
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    // Get the Authorization header value
    var authHeader = context.Request.Headers["Authorization"].ToString();
    AuthenticationHeaderValue? authHeaderValue;

    // Try parsing the Authorization header
    if (AuthenticationHeaderValue.TryParse(authHeader, out authHeaderValue))
    {
        if (authHeaderValue.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase) && authHeaderValue.Parameter!=null)
        {
            // Decode and validate the credentials
            var credentialBytes = Convert.FromBase64String(authHeaderValue.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');

            if (credentials.Length == 2)
            {
                var username = credentials[0];
                var password = credentials[1];

                // Validate username and password against predefined values
                if (username == _username && password == _password)
                {
                    await _next(context); // User is authenticated; proceed to next middleware
                    return;
                }
            }
        }
    }

    // If authentication fails, return a 401 Unauthorized response
    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }
}

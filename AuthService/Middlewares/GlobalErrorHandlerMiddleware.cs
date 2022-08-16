using Serilog;

namespace AuthService.Middlewares
{
    public class GlobalErrorHandlerMiddleware
    {
        private readonly RequestDelegate _next;

        public GlobalErrorHandlerMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            string errorMessage = String.Empty;
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                // log and rethrow exception
                Log.Error(ex, ex.Message);
            }
        }
    }

    public static class GlobalErrorHandlerMiddlewareExtension
    {
        public static IApplicationBuilder UseGlobalErrorHandler(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<GlobalErrorHandlerMiddleware>();
        }
    }
}

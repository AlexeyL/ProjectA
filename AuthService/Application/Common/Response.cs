using FluentValidation.Results;

namespace AuthService.Application.Common
{
    public interface IResponse
    {
        object? Result { get; }
        bool Success { get; }
        ValidationResult ValidationResult { get; }
    }

    public class Response : IResponse
    {
        public object? Result { get; private set; }
        public bool Success { get; private set; }
        public ValidationResult ValidationResult { get; private set; }

        public Response(bool success, ValidationResult validationResult, object? result = null)
        {
            Success = success;
            ValidationResult = validationResult;
            Result = result;
        }

    }
}

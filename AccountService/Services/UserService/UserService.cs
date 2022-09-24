using System.Security.Claims;

namespace AccountService.Services.UserService
{
    public class UserService : IUserService
    {
        public IHttpContextAccessor _httpContextAccessor { get; }
        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public string GetMyName()
        {
            var result = string.Empty;
            if (_httpContextAccessor.HttpContext != null)
            {
                result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }

            return result;
        }
        
    }
}

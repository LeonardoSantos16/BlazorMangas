using Blazored.LocalStorage;

namespace BlazorMangas.Services.Api
{
    public class CustomHttpHandler : DelegatingHandler // A classe DelegatingHandler permite interceptar
                                                       // e modificar requests Http antes que eles sejão enviados para o servidor
    {
        private readonly ILocalStorageService _localStorageService;
        public CustomHttpHandler(ILocalStorageService localStorageService)
        {
            _localStorageService = localStorageService;
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
                                                           CancellationToken cancellationToken)
        {
            if (request.RequestUri.AbsolutePath.ToLower().Contains("login") ||
                request.RequestUri.AbsolutePath.ToLower().Contains("register")) // se for login ou registrar envia o header sem o token
            {
                return await base.SendAsync(request, cancellationToken);
            }

            var jwtToken = await _localStorageService.GetItemAsync<string>("authToken"); // obtem o token

            if (!string.IsNullOrEmpty(jwtToken))
            {
                request.Headers.Add("Authorization", $"bearer {jwtToken}"); // coloca o token no header autorization do request
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }
}

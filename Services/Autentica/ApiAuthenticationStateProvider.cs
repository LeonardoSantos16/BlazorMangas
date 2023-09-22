using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorMangas.Services.Autentica
{
    public class ApiAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly ILocalStorageService _localStorage;

        public ApiAuthenticationStateProvider(ILocalStorageService localStorage)
        {
            _localStorage = localStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var savedToken = await _localStorage.GetItemAsync<string>("authToken"); //procurar pelo token no navegador 
            var expirationToken = await _localStorage.GetItemAsync<string>("tokenExpiration"); //procurar a data de expiração token no navegador 

            if (string.IsNullOrWhiteSpace(savedToken) || TokenExpirou(expirationToken))
            {
                MarkUserAsLoggedOut(); // Se o token for nulo ou token expirou marca o usuário como não logado
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())); // criando uma claims principal com usuário anonimo
            }

            return new AuthenticationState(new ClaimsPrincipal(
               new ClaimsIdentity(ParseClaimsFromJwt(savedToken), "jwt"))); // criando a claim principal com as informações do token, quando o token é válido
        }
        public void MarkUserAsAuthenticated(string email) // método para marcar o usuário como autenticado
        {
            var authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(new[]  // Criar um usuário com a informação do email passado como parâmetro
            {
           new Claim(ClaimTypes.Name, email)
        }, "apiauth"));

            var authState = Task.FromResult(new AuthenticationState(authenticatedUser)); // instância do estado de autenticação com a informação do usuário
            NotifyAuthenticationStateChanged(authState); // Notificar todos os componentes
        }

        public void MarkUserAsLoggedOut() // Marca o usuário como não autenticado
        {
            var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity()); // Cria a claims principal vázia, usuário anonimo
            var authState = Task.FromResult(new AuthenticationState(anonymousUser)); // Cria o estado de autenticação com o usuário anonimo
            NotifyAuthenticationStateChanged(authState); // Notificar todos os componentes
        }

        private bool TokenExpirou(string dataToken)
        {
            DateTime dataAtualUtc = DateTime.UtcNow;
            DateTime dataExpiracao =
                DateTime.ParseExact(dataToken, "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", null,
                System.Globalization.DateTimeStyles.RoundtripKind);

            if (dataExpiracao < dataAtualUtc)
            {
                return true;
            }
            return false;
        }
        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt) // Extrair informações do token
        {
            var claims = new List<Claim>();
            var payload = jwt.Split('.')[1];
            var jsonBytes = ParseBase64WithoutPadding(payload);
            var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

            keyValuePairs.TryGetValue(ClaimTypes.Role, out object roles);

            if (roles != null)
            {
                if (roles.ToString().Trim().StartsWith("["))
                {
                    var parsedRoles = JsonSerializer.Deserialize<string[]>(roles.ToString());
                    foreach (var parsedRole in parsedRoles)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, parsedRole));
                    }
                }
                else
                {
                    claims.Add(new Claim(ClaimTypes.Role, roles.ToString()));
                }
                keyValuePairs.Remove(ClaimTypes.Role);
            }

            claims.AddRange(keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString())));

            return claims;
        }

        private byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}

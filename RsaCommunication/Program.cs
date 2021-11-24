using Newtonsoft.Json;
using System.Text;
using RsaCommunication;
using System.Numerics;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors();
var app = builder.Build();
app.UseCors(opts => opts.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

var users = new List<User>
{
    new User("eduard.sheliemietiev@nure.ua", "qwerty", "3 Coconuts 🥥"),
    new User("admin@gmail.com", "12345", "1 Croissant 🥐"),
    new User("user@gmail.com", "QWERTY12345", "5 Cookies 🍪"),
};

var (serverPublicKey, serverPrivateKey) = Rsa.GenerateKeys(1024);

app.MapGet("/publicKey", async (HttpContext context) =>
{
    await context.Response.WriteAsJsonAsync(new
    {
        e = Convert.ToHexString(serverPublicKey.e.ToByteArray(true, true)),
        n = Convert.ToHexString(serverPublicKey.n.ToByteArray(true, true)),
    });
});

app.MapPost("/login", async (HttpContext context, ILogger<Program> logger) =>
{
    var (clientPublicKeyHex, requestCiphertext) = await context.Request.ReadFromJsonAsync<EncryptedMessage>();
    var clientPublicKey = new RsaPublicKey(
        new BigInteger(Convert.FromHexString(clientPublicKeyHex.e), true, true),
        new BigInteger(Convert.FromHexString(clientPublicKeyHex.n), true, true)
    );
    var requestPlaintextBytes = Rsa.Decrypt(Convert.FromHexString(requestCiphertext), serverPrivateKey);
    var requestPlaintext = Encoding.UTF8.GetString(requestPlaintextBytes);
    var (email, password) = JsonConvert.DeserializeObject<LoginModel>(requestPlaintext);

    var user = users.FirstOrDefault(u => u.Email == email && u.Password == password);
    if (user == null)
    {
        logger.LogInformation("Email: {email}, password: {password} not found.", email, password);
        context.Response.StatusCode = 403;
        return;
    }

    var responsePlaintext = JsonConvert.SerializeObject(new { balance = user.Balance });
    var responsePlaintextBytes = Encoding.UTF8.GetBytes(responsePlaintext);
    var responseCiphertext = Rsa.Encrypt(responsePlaintextBytes, clientPublicKey);
    await context.Response.WriteAsJsonAsync(new { Content = Convert.ToHexString(responseCiphertext) });
});

app.Run();

public record EncryptedMessage(RsaPublicKeyHex publicKey, string Content);

public record RsaPublicKeyHex(string e, string n);

public record LoginModel(string Email, string Password);

public record User(string Email, string Password, string Balance);

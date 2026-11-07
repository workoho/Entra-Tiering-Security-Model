# Builds the exception that Invoke-MgGraphRequest throws for an HTTP error, without a network call.
# Written in C# so that the same type works in Windows PowerShell 5.1 and PowerShell 7.
if (-not ('FakeGraphException' -as [type])) {
    Add-Type -TypeDefinition @'
public enum FakeGraphStatus { Forbidden = 403, NotFound = 404 }

public class FakeGraphContent {
    private readonly string body;
    public FakeGraphContent(string body) { this.body = body; }
    public System.Threading.Tasks.Task<string> ReadAsStringAsync() { return System.Threading.Tasks.Task.FromResult(body); }
}

public class FakeGraphResponse {
    public FakeGraphStatus StatusCode;
    public FakeGraphContent Content;
}

public class FakeGraphException : System.Exception {
    public FakeGraphResponse Response;
    public FakeGraphException(int status, string code, string message) : base(message) {
        Response = new FakeGraphResponse();
        Response.StatusCode = (FakeGraphStatus)status;
        Response.Content = new FakeGraphContent("{\"error\":{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}}");
    }
}
'@
}

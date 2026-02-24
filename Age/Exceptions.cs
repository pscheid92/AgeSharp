namespace Age;

public class AgeException : Exception
{
    public AgeException(string message) : base(message) { }
    public AgeException(string message, Exception inner) : base(message, inner) { }
}

public class AgeHeaderException : AgeException
{
    public AgeHeaderException(string message) : base(message) { }
    public AgeHeaderException(string message, Exception inner) : base(message, inner) { }
}

public class AgeHmacException : AgeException
{
    public AgeHmacException(string message) : base(message) { }
}

public class AgePayloadException : AgeException
{
    public AgePayloadException(string message) : base(message) { }
    public AgePayloadException(string message, Exception inner) : base(message, inner) { }
}

public class AgeArmorException : AgeException
{
    public AgeArmorException(string message) : base(message) { }
}

public class NoIdentityMatchException : AgeException
{
    public NoIdentityMatchException() : base("no identity matched any recipient stanza") { }
}

public class AgePluginException : AgeException
{
    public AgePluginException(string message) : base(message) { }
    public AgePluginException(string message, Exception inner) : base(message, inner) { }
}

namespace Application.Features.Auth.Login;

using Application.Abstractions;
using Application.Abstractions.Data;
using Application.Abstractions.Messaging;
using Domain.Common;
using Microsoft.EntityFrameworkCore;

public sealed class LoginCommandHandler : 
    ICommandHandler<LoginCommand, Result<LoginResponse>>
{
    private readonly IAppDbContext dbContext;
    private readonly IPasswordHasher passwordHasher;
    private readonly ITokenService tokenService;
    private readonly TimeProvider timeProvider;

    public LoginCommandHandler(
        IAppDbContext dbContext,
        IPasswordHasher passwordHasher,
        ITokenService tokenService,
        TimeProvider timeProvider)
    {
        this.dbContext = dbContext;
        this.passwordHasher = passwordHasher;
        this.tokenService = tokenService;
        this.timeProvider = timeProvider;
    }

    public async Task<Result<LoginResponse>> HandleAsync(
        LoginCommand command,
        CancellationToken cancellationToken = default)
    {
        var email = command.Email.Trim().ToLowerInvariant();

        var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == email, cancellationToken);

        // Identical error for "no such user" and "wrong password" - prevents user enumeration
        if (user is null || !passwordHasher.Verify(command.Password, user.PasswordHash))
        {
            return Result<LoginResponse>.Failure(Error.Validation(
                "Auth.InvalidCredentials", "Invalid email or password."));
        }

        user.LastLoginAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        await dbContext.SaveChangesAsync(cancellationToken);

        return Result<LoginResponse>.Success(new LoginResponse(
            tokenService.GenerateAccessToken(user),
            tokenService.GetAccessTokenExpiry(),
            user.Role.ToString(),
            $"{user.FirstName} {user.LastName}"
        ));
    }
}

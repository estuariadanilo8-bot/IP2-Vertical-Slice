namespace Application.Features.Auth.Register;

using Application.Abstractions;
using Application.Abstractions.Data;
using Application.Abstractions.Messaging;
using Domain.Common;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;

public sealed class RegisterCommandHandler :
    ICommandHandler<RegisterCommand, Result<RegisterResponse>>
{
    private readonly IAppDbContext _dbContext;
    private readonly IPasswordHasher _passwordHasher;

    public RegisterCommandHandler(
        IAppDbContext dbContext,
        IPasswordHasher passwordHasher)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
    }

    public async Task<Result<RegisterResponse>> HandleAsync(
        RegisterCommand command,
        CancellationToken cancellationToken = default)
    {
        var email = command.Email.Trim().ToLowerInvariant();

        var exists = await _dbContext.Users.AnyAsync(u => u.Email == email, cancellationToken);
        if (exists)
        {
            return Result<RegisterResponse>.Failure(Error.Validation(
                "Auth.EmailAlreadyRegistered",
                "An account with this email address already exists."));
        }

        // Unrecognized or omitted Role defaults to Student
        var role = Enum.TryParse<UserRole>(command.Role, ignoreCase: true, out var parsedRole)
            ? parsedRole
            : UserRole.Student;

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            PasswordHash = _passwordHasher.Hash(command.Password),
            FirstName = command.FirstName.Trim(),
            LastName = command.LastName.Trim(),
            Role = role,
            IsActive = true
        };

        var student = await _dbContext.Students
            .FirstOrDefaultAsync(s => s.Email == email, cancellationToken);
        if (student is not null)
        {
            user.StudentId = student.Id;
        }

        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return Result<RegisterResponse>.Success(new RegisterResponse(
            user.Id, user.Email, user.FirstName, user.LastName, user.Role.ToString()));
    }
}
import { DeleteUserUseCase } from '@/domain/users/use-cases/delete-user.use-case';
import { UserRepository } from '@/domain/users/repositories/user.repository';
import { UserNotFoundError } from '@/domain/users/errors/user.errors';

describe('DeleteUserUseCase', () => {
  const makeSut = () => {
    const repo: jest.Mocked<UserRepository> = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      deleteById: jest.fn(),
    };
    const sut = new DeleteUserUseCase(repo);
    return { sut, repo };
  };

  it('deletes when id exists (happy path)', async () => {
    const { sut, repo } = makeSut();
    repo.deleteById.mockResolvedValue(true);
    await expect(sut.exec({ userId: 'some-id' })).resolves.toBeUndefined();
    expect(repo.deleteById).toHaveBeenCalledTimes(1);
    expect(repo.deleteById).toHaveBeenCalledWith('some-id');
    expect(repo.findById).not.toHaveBeenCalled();
    expect(repo.findByEmail).not.toHaveBeenCalled();
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('throws UserNotFoundError when id does not exist', async () => {
    const { sut, repo } = makeSut();
    repo.deleteById.mockResolvedValue(false);
    await expect(sut.exec({ userId: 'missing-id' })).rejects.toThrow(
      UserNotFoundError,
    );
    expect(repo.deleteById).toHaveBeenCalledWith('missing-id');
  });

  it('propagates repository errors', async () => {
    const { sut, repo } = makeSut();
    repo.deleteById.mockRejectedValue(new Error('db failure'));
    await expect(sut.exec({ userId: 'x' })).rejects.toThrow('db failure');
  });
});

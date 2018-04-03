import os
import git


def is_git_dir(path):
    if not (os.path.exists(path) and os.path.isdir(path)):
        return False

    try:
        git.Repo(path)
    except git.exc.InvalidGitRepositoryError as e:
        return False

    return True


def enumerate_changed_files(path):
    repo = git.Repo(path)

    files = repo.untracked_files

    for file in repo.head.commit.diff(None):
        files.append(file.b_path)

    return files

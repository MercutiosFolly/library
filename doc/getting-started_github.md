# Github Cheat Sheet
Intended to answer some commonly asks questions not as a guide.

## Tools
* This interactive cheat sheet give you some good visuals:

    https://ndpsoftware.com/git-cheatsheet.html#loc=stash;

* If you use vim, I highly recommend the gitgutter and NERDtree plug ins:

    https://vimawesome.com/plugin/vim-gitgutter
    https://vimawesome.com/plugin/nerdtree-red

    Follow the instruction on the nerdtree page to install the git extension for it.

## Configuration

Your global configurations get applied to all your repos but each repo has its own
configuration that overrides the global. You will need to set your `user.name` and
`user.email` at a minimum. Leave the `--global` flag off to access the repo config.

Editing the global config:

```bash
# Command template
git config --global <key> <value>

# List your git configuration for your current location
git config -l

# Setting up your name and email
git config --global user.name bob
git config --global user.email bob@bobshouse.com

# Alternatively, if you know what you're doing, you can edit the files
vim ~/.gitconfig          # The global config
vim project/.git/config   # The project (repo) specific config
```

If you are using a pgp key for commit signing, you will want to setup the following:

```bash
git config --global user.signingkey <keyvalue>
git config --global commit.gpgsign true
git config --global gpg.program /usr/bin/gpg2 #Wherever your gpg program is
```
    
## Cloning

To clone repos:

```bash
git clone https://github.com/username/reponame.git # For https access
git clone git@github.com:username/reponame         # If you have ssh keys configured

# If you have a project with submodules:
git submodule init
git submodule update

# Alternatively, you can just clone recursively
git clone --recurse-submodule https://github.com/username/reponame.git
```

## Commiting

To tag an issue in a commit, simply include `closes #issueNumber` or `fixes #issuenumber` or
`resolves #issueNumber`.

Use `git pull --rebase` to avoid merge commits and squash commits to keep history clean

Use `git merge --squash` to roll up all commits on a merging branch. Keeps history clean

If you have pgp keys setup, sign with `-S`

Use proper etiquette when writing commit messages:

    1. Separate subject from body with blank line
    2. Keep subject under 50 characters
    3. Capitalize the subject line
    4. Do not end subject with period
    5. Use the imperative mood in the subject ( "Add docs", "Fix bug")
    6. Wrap the body at 72 chars
    7. Use the body to explain what and why, not how.

## Branches

To switch to a branch that only exists on the remote:

```bash
git pull                  # or git fetch
git branch -a             # will list remote branches
git checkout branch-name  # Don't need the `origin` or `remote` prefix
```

## Fixing Mistakes

To reset your repo to the last commit:

    `git reset --hard`

To restore file to the last commited state:

    `git checkout <filename>`

## Pushing/Pulling

Instead of typing `git push origin my-branch` everytime, the upstream can be set so
you can simply use `git push`:

    `git push -u origin my-branch`




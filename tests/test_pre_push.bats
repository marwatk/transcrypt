#!/usr/bin/env bats

load "$BATS_TEST_DIRNAME/_test_helper.bash"

function setup {
  init_git_repo
  init_transcrypt
  REMOTE="$BATS_TEST_TMPDIR/remote.git"
  git init --quiet --bare -b main "$REMOTE"
  git remote add origin "$REMOTE"
}

# Store file $1 with content $2 without the clean filter, as a clone without
# transcrypt configured or a tool that ignores filters would
function store_unencrypted {
  printf '%s\n' "$2" > "$1"
  blob=$(git hash-object -w --no-filters "$1")
  git update-index --add --cacheinfo "100644,$blob,$1"
}

# The commit the remote's main branch points to, or nothing
function remote_main {
  git --git-dir="$REMOTE" rev-parse -q --verify refs/heads/main || true
}

@test "pre-push: hook installed on init" {
  [ -x .git/hooks/pre-push ]
  cmp .git/hooks/pre-push .git/hooks/pre-push-crypt
  grep -q 'pre_push' .git/hooks/pre-push
}

@test "pre-push: allow pushing encrypted files" {
  encrypt_named_file secret.env "SECRET=1"

  run git push -q origin main
  [ "$status" -eq 0 ]
  [ "$(remote_main)" = "$(git rev-parse HEAD)" ]
}

@test "pre-push: refuse a file stored unencrypted where .gitattributes marks it" {
  encrypt_named_file secret.env "SECRET=1"
  git push -q origin main
  pushed=$(git rev-parse HEAD)

  store_unencrypted secret.env "SECRET=2"
  git commit -q --no-verify -m "Unencrypted"

  run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to push unencrypted secrets to origin"* ]]
  [[ "$output" == *"secret.env: not encrypted, but .gitattributes marks it for encryption"* ]]
  [ "$(remote_main)" = "$pushed" ]
}

@test "pre-push: refuse plaintext in an earlier commit even if a later one removes it" {
  encrypt_named_file secret.env "SECRET=1"
  store_unencrypted secret.env "SECRET=2"
  git commit -q --no-verify -m "Unencrypted"
  git rm -q -f secret.env
  git commit -q -m "Remove it"

  run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"secret.env: not encrypted"* ]]
  [ -z "$(remote_main)" ]
}

@test "pre-push: refuse a secret decrypted after its rule was removed" {
  encrypt_named_file secret.env "SECRET=1"
  git push -q origin main

  echo "" > .gitattributes
  git add .gitattributes
  git commit -q -m "Drop the rule"
  echo "SECRET=2" > secret.env
  git add secret.env
  git commit -q --no-verify -m "Edit secret"

  run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"secret.env: not encrypted"* ]]
}

@test "pre-push: refuse a copy of a secret outside the encrypted patterns" {
  encrypt_named_file secret.env "SECRET=a-long-enough-secret-value"
  cp secret.env secret.env.bak
  git add secret.env.bak
  git commit -q -m "Backup"

  run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"secret.env.bak: same content as the encrypted file secret.env"* ]]
}

@test "pre-push: refuse a secret moved outside the encrypted patterns" {
  encrypt_named_file secret.env "SECRET=a-long-enough-secret-value"
  git push -q origin main
  git mv secret.env config.txt
  git commit -q -a -m "Move"

  run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"config.txt: not encrypted, but it was before this commit"* || "$output" == *"config.txt: same content as the encrypted file"* ]]
}

@test "pre-push: don't recheck history already on the remote" {
  echo "OLD=1" > old.env
  git add old.env
  git commit -q -m "Plaintext from before transcrypt"
  git push -q --no-verify origin main
  echo '"old.env" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  git add .gitattributes
  git add --renormalize old.env
  git commit -q -m "Encrypt old.env"

  run git push origin main
  [ "$status" -eq 0 ]
}

@test "pre-push: a new branch only checks commits the remote doesn't have" {
  echo "OLD=1" > old.env
  git add old.env
  git commit -q -m "Plaintext from before transcrypt"
  git push -q --no-verify origin main
  echo '"old.env" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  git add .gitattributes
  git commit -q --no-verify -m "Rule without re-encrypting"
  git checkout -q -b feature
  echo "x" > readme.txt
  git add readme.txt
  git commit -q --no-verify -m "Unrelated"

  run git push origin feature
  [ "$status" -eq 0 ]
}

@test "pre-push: refuse from a clone where transcrypt isn't configured" {
  encrypt_named_file secret.env "SECRET=1"
  git push -q origin main
  hook="$PWD/.git/hooks/pre-push-crypt"

  # A fresh clone, with the hook from a template and transcrypt on the PATH
  git clone -q "$REMOTE" "$BATS_TEST_TMPDIR/clone"
  cd "$BATS_TEST_TMPDIR/clone"
  git config user.name "John Doe"
  git config user.email johndoe@example.com
  cp "$hook" .git/hooks/pre-push
  mkdir "$BATS_TEST_TMPDIR/bin"
  ln -s "$TRANSCRYPT" "$BATS_TEST_TMPDIR/bin/transcrypt"
  echo "SECRET=2" > secret.env
  git commit -q -a -m "Edit without transcrypt"

  PATH="$BATS_TEST_TMPDIR/bin:$PATH" run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"secret.env: not encrypted"* ]]
}

@test "pre-push: refuse from an unconfigured clone when transcrypt isn't installed" {
  encrypt_named_file secret.env "SECRET=1"
  git push -q origin main
  hook="$PWD/.git/hooks/pre-push-crypt"

  git clone -q "$REMOTE" "$BATS_TEST_TMPDIR/clone"
  cd "$BATS_TEST_TMPDIR/clone"
  git config user.name "John Doe"
  git config user.email johndoe@example.com
  cp "$hook" .git/hooks/pre-push
  echo "x" > readme.txt
  git add readme.txt
  git commit -q -m "Anything"

  # A PATH with git but no transcrypt
  mkdir "$BATS_TEST_TMPDIR/bin"
  ln -s "$(command -v git)" "$BATS_TEST_TMPDIR/bin/git"
  PATH="$BATS_TEST_TMPDIR/bin:/usr/bin:/bin" run git push origin main
  [ "$status" -ne 0 ]
  [[ "$output" == *"transcrypt, which is not installed; refusing to push"* ]]
}

@test "pre-push: the template hook allows pushes from repositories without transcrypt" {
  hook="$PWD/.git/hooks/pre-push-crypt"
  git init -q -b main "$BATS_TEST_TMPDIR/plain"
  git init -q --bare -b main "$BATS_TEST_TMPDIR/plain-remote.git"
  cd "$BATS_TEST_TMPDIR/plain"
  git config user.name "John Doe"
  git config user.email johndoe@example.com
  cp "$hook" .git/hooks/pre-push
  echo "hello" > readme.txt
  git add readme.txt
  git commit -q -m "Plain"
  git remote add origin "$BATS_TEST_TMPDIR/plain-remote.git"

  run git push -q origin main
  [ "$status" -eq 0 ]
}

@test "pre-push: --uninstall removes the hook" {
  run "$TRANSCRYPT" --uninstall --yes
  [ "$status" -eq 0 ]
  [ ! -e .git/hooks/pre-push ]
  [ ! -e .git/hooks/pre-push-crypt ]
}

@test "pre-push: an existing pre-push hook is kept, with a warning" {
  "$TRANSCRYPT" --uninstall --yes > /dev/null
  git reset -q --hard
  printf '#!/bin/sh\nexit 0\n' > .git/hooks/pre-push
  chmod +x .git/hooks/pre-push

  run "$TRANSCRYPT" --cipher=aes-256-cbc --password='abc 123' --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"Cannot install Git pre-push hook script because file already exists"* ]]
  [ "$(cat .git/hooks/pre-push)" = "$(printf '#!/bin/sh\nexit 0')" ]
}

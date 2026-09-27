#!/usr/bin/env bats

load "$BATS_TEST_DIRNAME/_test_helper.bash"

# Print the attribute rule transcrypt writes for pattern $1
function rule {
  echo "$1  filter=crypt diff=crypt merge=crypt"
}

# Succeed if file $1 is stored encrypted in the index
function staged_encrypted {
  [[ "$(git show ":$1" --no-textconv)" == U2FsdGVk* ]]
}

@test "add: repeated --add keeps every pattern" {
  run "$TRANSCRYPT" --add a.env --add=b.env
  [ "$status" -eq 0 ]
  grep -qxF "$(rule a.env)" .gitattributes
  grep -qxF "$(rule b.env)" .gitattributes
}

@test "add: a directory pattern matches the files inside it" {
  mkdir -p secrets/nested keys
  echo "A=1" > secrets/nested/a.env
  echo "K=1" > keys/k.pem

  run "$TRANSCRYPT" --add secrets/ --add keys
  [ "$status" -eq 0 ]
  grep -qxF "$(rule 'secrets/**')" .gitattributes
  grep -qxF "$(rule 'keys/**')" .gitattributes

  git add .gitattributes secrets keys
  staged_encrypted secrets/nested/a.env
  staged_encrypted keys/k.pem
}

@test "add: paths from a subdirectory are relative to it" {
  mkdir -p sub/config
  echo "A=1" > sub/config/app.env
  echo "B=1" > sub/b.env
  cd sub

  "$TRANSCRYPT" --add config/app.env
  "$TRANSCRYPT" --add ./b.env
  cd ..
  grep -qxF "$(rule sub/config/app.env)" .gitattributes
  grep -qxF "$(rule sub/b.env)" .gitattributes

  git add .gitattributes sub
  staged_encrypted sub/config/app.env
  staged_encrypted sub/b.env
}

@test "add: git add-crypt from a subdirectory is relative to it" {
  mkdir -p sub/config
  echo "A=1" > sub/config/app.env
  cd sub

  git add-crypt config/app.env
  cd ..
  grep -qxF "$(rule sub/config/app.env)" .gitattributes
}

@test "add: absolute paths inside the repository work" {
  mkdir config
  echo "A=1" > config/app.env

  "$TRANSCRYPT" --add "$(git rev-parse --show-toplevel)/config/app.env"
  grep -qxF "$(rule config/app.env)" .gitattributes
}

@test "add: absolute paths through a symlinked directory work" {
  mkdir config
  echo "A=1" > config/app.env
  ln -s "$(git rev-parse --show-toplevel)/config" "$BATS_TEST_TMPDIR/linked"

  "$TRANSCRYPT" --add "$BATS_TEST_TMPDIR/linked/app.env"
  grep -qxF "$(rule config/app.env)" .gitattributes
}

@test "add: names with spaces are quoted so they match" {
  echo "KEY=1" > "Google Service Account.json"

  run "$TRANSCRYPT" --add "Google Service Account.json"
  [ "$status" -eq 0 ]
  grep -qxF "$(rule '"Google Service Account.json"')" .gitattributes

  git add .gitattributes "Google Service Account.json"
  staged_encrypted "Google Service Account.json"
}

@test "add: a rule is never glued onto a last line without a newline" {
  printf '* text=auto' > .gitattributes
  echo "A=1" > secret.env

  run "$TRANSCRYPT" --add secret.env
  [ "$status" -eq 0 ]
  [ "$(sed -n 1p .gitattributes)" = "* text=auto" ]
  [ "$(sed -n 2p .gitattributes)" = "$(rule secret.env)" ]
  git add .gitattributes secret.env
  staged_encrypted secret.env
}

@test "add: refuse a pattern that would encrypt .gitattributes" {
  cp .gitattributes before

  run "$TRANSCRYPT" --add '.*'
  [ "$status" -eq 1 ]
  [[ "$output" == *"would encrypt .gitattributes itself"* ]]
  cmp .gitattributes before
}

@test "add: refuse negative patterns and patterns outside the repository" {
  run "$TRANSCRYPT" --add '!secret.env'
  [ "$status" -eq 1 ]
  [[ "$output" == *"does not support negative patterns"* ]]

  run "$TRANSCRYPT" --add ../secret.env
  [ "$status" -eq 1 ]
  [[ "$output" == *'without ".."'* ]]

  run "$TRANSCRYPT" --add /etc/passwd
  [ "$status" -eq 1 ]
  [[ "$output" == *"is not inside the repository"* ]]
}

@test "add: refuse when transcrypt isn't configured" {
  "$TRANSCRYPT" --flush-credentials --yes > /dev/null

  run "$TRANSCRYPT" --add secret.env
  [ "$status" -eq 1 ]
  run grep -c secret.env .gitattributes
  [ "$output" = "0" ]
}

@test "add: warn about files already in git unencrypted" {
  echo "SECRET=1" > secret.env
  git add secret.env
  git commit -q -m "Add secret before encrypting it"

  run "$TRANSCRYPT" --add secret.env
  [ "$status" -eq 0 ]
  [[ "$output" == *"these files are already in git unencrypted:"* ]]
  [[ "$output" == *"  secret.env"* ]]

  git add .gitattributes
  git add --renormalize -- secret.env
  staged_encrypted secret.env
}

@test "add: warn when a pattern matches no files" {
  run "$TRANSCRYPT" --add does-not-exist.env
  [ "$status" -eq 0 ]
  [[ "$output" == *"no files match the new pattern yet"* ]]
}

@test "add: warn when a pattern matches only by ignoring case" {
  git config core.ignorecase true
  echo "A=1" > Secret.env

  run "$TRANSCRYPT" --add secret.env
  [ "$status" -eq 0 ]
  [[ "$output" == *"match only because this file system ignores case"* ]]
  [[ "$output" == *"  Secret.env"* ]]
}

@test "add: refuse a symlinked .gitattributes, which git ignores" {
  mv .gitattributes attributes
  ln -s attributes .gitattributes

  run "$TRANSCRYPT" --add secret.env
  [ "$status" -eq 1 ]
  [[ "$output" == *"because it is a symlink"* ]]
}

@test "add: a global core.attributesFile is ignored" {
  export GIT_CONFIG_GLOBAL="$BATS_TEST_TMPDIR/global-config"
  git config --global core.attributesFile "$BATS_TEST_TMPDIR/global-attributes"

  run "$TRANSCRYPT" --add secret.env
  [ "$status" -eq 0 ]
  grep -qxF "$(rule secret.env)" .gitattributes
  [ ! -e "$BATS_TEST_TMPDIR/global-attributes" ]
}

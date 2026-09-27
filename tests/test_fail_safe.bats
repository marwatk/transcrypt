#!/usr/bin/env bats

load "$BATS_TEST_DIRNAME/_test_helper.bash"

# Print the content of a file committed at HEAD exactly as stored
function stored {
  git show "HEAD:$1" --no-textconv
}

@test "fail-safe: clean encrypts its input even when the working-tree file is missing" {
  run bash -c "printf 'A=1\n' | '$TRANSCRYPT' clean context=default missing_file 2>/dev/null"
  [ "$status" -eq 0 ]
  [[ "$output" == U2FsdGVk* ]]
}

@test "fail-safe: merge reports a modify/delete conflict on an encrypted file" {
  printf 'A=1\nB=2\nC=3\n' > secret.env
  encrypt_named_file secret.env

  git checkout -b feature
  printf 'A=1\nB=ROTATED\nC=3\n' > secret.env
  git commit -qam "Rotate B"

  git checkout -q main
  git rm -q secret.env
  git commit -qm "Delete secret"

  run git merge --no-edit feature
  [ "$status" -ne 0 ]
  [[ "$output" == *"CONFLICT (modify/delete)"* ]]
  [ "$(git cat-file --textconv feature:secret.env)" = "$(printf 'A=1\nB=ROTATED\nC=3')" ]
}

@test "fail-safe: rebase keeps an edit to an encrypted file deleted upstream" {
  printf 'A=1\nB=2\nC=3\n' > secret.env
  encrypt_named_file secret.env

  git checkout -b feature
  printf 'A=1\nB=ROTATED\nC=3\n' > secret.env
  git commit -qam "Rotate B"

  git checkout -q main
  git rm -q secret.env
  git commit -qm "Delete secret"

  git checkout -q feature
  run git rebase main
  [ "$status" -ne 0 ]
  [[ "$output" == *"CONFLICT (modify/delete)"* ]]
  git rebase --abort
}

@test "fail-safe: cherry-pick never overwrites uncommitted edits to an encrypted file" {
  printf 'a=1\nb=2\nc=3\nd=4\ne=5\n' > s.env
  encrypt_named_file s.env

  git checkout -q -b other
  printf 'a=OTHER\nb=2\nc=3\nd=4\ne=5\n' > s.env
  git commit -qam other
  git checkout -q main
  printf 'a=1\nb=2\nc=3\nd=4\ne=MAIN\n' > s.env
  git commit -qam main

  printf 'a=1\nb=2\nc=MY-UNCOMMITTED-WORK\nd=4\ne=MAIN\n' > s.env
  run git cherry-pick other
  [ "$status" -ne 0 ]
  [ "$(cat s.env)" = "$(printf 'a=1\nb=2\nc=MY-UNCOMMITTED-WORK\nd=4\ne=MAIN')" ]
  [ "$(sed -n 3p s.env)" = "c=MY-UNCOMMITTED-WORK" ]
}

@test "fail-safe: merge preserves missing and extra trailing newlines" {
  printf 'a=1\nb=2\nc=3\nd=4\ne=5\n\n\n' > extra.env
  printf 'a=1\nb=2\nc=3\nd=4\ne=5' > none.env
  encrypt_named_file extra.env
  encrypt_named_file none.env

  git checkout -q -b other
  printf 'a=OTHER\nb=2\nc=3\nd=4\ne=5\n\n\n' > extra.env
  printf 'a=OTHER\nb=2\nc=3\nd=4\ne=5' > none.env
  git commit -qam other
  git checkout -q main
  printf 'a=1\nb=2\nc=3\nd=4\ne=MAIN\n\n\n' > extra.env
  printf 'a=1\nb=2\nc=3\nd=4\ne=MAIN' > none.env
  git commit -qam main

  run git merge --no-edit other
  [ "$status" -eq 0 ]
  printf 'a=OTHER\nb=2\nc=3\nd=4\ne=MAIN\n\n\n' > expected_extra
  printf 'a=OTHER\nb=2\nc=3\nd=4\ne=MAIN' > expected_none
  cmp extra.env expected_extra
  cmp none.env expected_none
  check_repo_is_clean
}

@test "fail-safe: binary encrypted file with NUL bytes conflicts instead of merging corrupted" {
  printf 'KEY\0\0\001\002\nline2\nline3\n' > key.p12
  encrypt_named_file key.p12

  git checkout -q -b other
  printf 'KEY\0\0\001\002\nline2\nOTHER\n' > key.p12
  git commit -qam other
  git checkout -q main
  printf 'MAIN\0\0\001\002\nline2\nline3\n' > key.p12
  cp key.p12 ours.p12
  git commit -qam main

  run git merge --no-edit other
  [ "$status" -ne 0 ]
  cmp key.p12 ours.p12
}

@test "fail-safe: wrong password leaves files encrypted rather than writing garbage" {
  encrypt_named_file sensitive_file "My secret content"
  git config transcrypt.password 'WRONG'

  rm sensitive_file
  run git checkout -- sensitive_file
  [ "$status" -eq 0 ]
  [[ "$output" == *"cannot decrypt sensitive_file with the configured password"* ]]
  [ "$(cat sensitive_file)" = "$(stored sensitive_file)" ]
  check_repo_is_clean
}

@test "fail-safe: wrong password that passes the CBC padding check still leaves files encrypted" {
  encrypt_named_file sensitive_file "My secret content"
  stored sensitive_file > ciphertext

  # About 1 in 256 wrong passwords decrypt without an openssl error; find one
  found=''
  for i in $(seq 1 4000); do
    if ENC_PASS="wrong-$i" openssl enc -d -aes-256-cbc -md MD5 -pass env:ENC_PASS -a -in ciphertext >/dev/null 2>&1; then
      found="wrong-$i"
      break
    fi
  done
  [ -n "$found" ]
  git config transcrypt.password "$found"

  rm sensitive_file
  run git checkout -- sensitive_file
  [ "$status" -eq 0 ]
  [ "$(cat sensitive_file)" = "$(cat ciphertext)" ]
}

@test "fail-safe: textconv with a wrong password shows only the ciphertext" {
  encrypt_named_file sensitive_file "My secret content"
  stored sensitive_file > ciphertext
  git config transcrypt.password 'WRONG'

  run "$TRANSCRYPT" textconv context=default ciphertext
  [ "$status" -eq 0 ]
  [ "$output" = "$(cat ciphertext)" ]
}

@test "fail-safe: smudge passes large unencrypted content through untruncated" {
  echo '"big.txt" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  seq 1 40000 > big.txt
  cp big.txt expected
  # Store it unencrypted, as a clone without transcrypt would
  blob=$(git hash-object -w --no-filters big.txt)
  git update-index --add --cacheinfo "100644,$blob,big.txt"
  git add .gitattributes
  git commit -q --no-verify -m "Unencrypted big file"

  rm big.txt
  git checkout -- big.txt
  cmp big.txt expected
}

@test "fail-safe: --verify passes when every encrypted file verifies" {
  encrypt_named_file sensitive_file "My secret content"

  run "$TRANSCRYPT" --verify
  [ "$status" -eq 0 ]
  [ "$output" = "All committed encrypted files decrypt and verify." ]
}

@test "fail-safe: --verify reports plaintext and moved encrypted files" {
  encrypt_named_file sensitive_file "My secret content"
  encrypt_named_file moved_file "Moved content"

  # A file moved with git mv keeps the salt derived from its old path
  echo '"new_name" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  git add .gitattributes
  git mv moved_file new_name
  git commit -q -m "Move file"

  # A file stored unencrypted, as a clone without transcrypt would
  echo '"plain_file" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  echo "Not encrypted" > plain_file
  blob=$(git hash-object -w --no-filters plain_file)
  git update-index --add --cacheinfo "100644,$blob,plain_file"
  git add .gitattributes
  git commit -q --no-verify -m "Unencrypted file"

  run "$TRANSCRYPT" --verify
  [ "$status" -eq 1 ]
  [[ "$output" == *"UNVERIFIED     new_name"* ]]
  [[ "$output" == *"NOT ENCRYPTED  plain_file"* ]]
  [[ "$output" != *"sensitive_file"* ]]
}

@test "fail-safe: --verify works from a subdirectory" {
  mkdir sub
  encrypt_named_file sensitive_file "My secret content"
  cd sub

  run "$TRANSCRYPT" --verify
  [ "$status" -eq 0 ]
  [ "$output" = "All committed encrypted files decrypt and verify." ]
}

@test "fail-safe: --rekey handles names with spaces and never stages unrelated files" {
  encrypt_named_file "api keys.json" "API_KEY=1"
  echo "untracked plaintext" > keys.json

  run "$TRANSCRYPT" --rekey --password='new password' --yes
  [ "$status" -eq 0 ]
  [ ! -e api ]
  [ "$(git diff --cached --name-only)" = "api keys.json" ]
  git commit -q -m "Rekey"

  git show 'HEAD:api keys.json' --no-textconv > ciphertext
  ENC_PASS='new password' openssl enc -d -aes-256-cbc -md MD5 -pass env:ENC_PASS -a -in ciphertext > plaintext 2>/dev/null
  [ "$(cat plaintext)" = "API_KEY=1" ]
}

@test "fail-safe: --upgrade creates no stray files for names with spaces" {
  encrypt_named_file "a b.env" "A=1"

  run "$TRANSCRYPT" --upgrade --yes
  [ "$status" -eq 0 ]
  [ ! -e a ]
  [ ! -e b.env ]
  [ -z "$(git status --porcelain)" ]
}

@test "fail-safe: --upgrade completes with other files in the crypt directory" {
  encrypt_named_file sensitive_file "My secret content"
  # e.g. left behind by --export-gpg
  echo "exported" > .git/crypt/someone@example.com.asc

  run "$TRANSCRYPT" --upgrade --yes
  [ "$status" -eq 0 ]
  [ -x .git/crypt/transcrypt ]
  [ "$(git config --get filter.crypt.required)" = "true" ]
  [ -f .git/crypt/someone@example.com.asc ]
}

@test "fail-safe: --uninstall completes when merge.renormalize is already unset" {
  encrypt_named_file sensitive_file "My secret content"
  git config --unset merge.renormalize

  run "$TRANSCRYPT" --uninstall --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"completely removed"* ]]
  run grep -c "filter=crypt" .gitattributes
  [ "$output" = "0" ]
}

@test "fail-safe: --upgrade keeps passwords containing '|'" {
  "$TRANSCRYPT" --flush-credentials --yes > /dev/null
  "$TRANSCRYPT" --cipher=aes-256-cbc --password='a|b|c' --yes > /dev/null
  encrypt_named_file sensitive_file "My secret content"

  run "$TRANSCRYPT" --upgrade --yes
  [ "$status" -eq 0 ]
  [ "$(git config --get transcrypt.password)" = 'a|b|c' ]
}

@test "fail-safe: --flush-credentials never deletes untracked files with glob-like names" {
  # The brackets are escaped so the pattern matches the literal name
  printf '%s\n' 'key\[12\].env filter=crypt diff=crypt merge=crypt' >> .gitattributes
  echo "KEY=1" > "key[12].env"
  git add .gitattributes "key[12].env"
  git commit -q -m "Add key[12].env"
  echo "untracked" > key1.env

  run "$TRANSCRYPT" --flush-credentials --yes
  [ "$status" -eq 0 ]
  [ "$(cat key1.env)" = "untracked" ]
  [ "$(cat 'key[12].env')" = "$(git show 'HEAD:key[12].env' --no-textconv)" ]
}

@test "fail-safe: forced init keeps a staged but uncommitted encrypted file" {
  encrypt_named_file sensitive_file "My secret content"
  "$TRANSCRYPT" --flush-credentials --yes > /dev/null
  echo '"new.env" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  echo "NEW=1" > new.env
  git add .gitattributes new.env

  run "$TRANSCRYPT" --force --cipher=aes-256-cbc --password='abc 123' --yes
  [ "$status" -eq 0 ]
  [ -f new.env ]
}

@test "fail-safe: clean refuses to encrypt without a password" {
  echo '"secret.env" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  git add .gitattributes
  git config --unset transcrypt.password
  echo "SECRET=1" > secret.env

  run git add secret.env
  [ "$status" -ne 0 ]
  [[ "$output" == *"no cipher and password configured for context default; refusing to store secret.env"* ]]
  [ -z "$(git ls-files secret.env)" ]
}

@test "fail-safe: context filters are required, so a failure never stores plaintext" {
  "$TRANSCRYPT" --context=super --cipher=aes-256-cbc --password=super-pw --yes > /dev/null
  [ "$(git config --get filter.crypt-super.required)" = "true" ]

  echo '"top-secret" filter=crypt-super diff=crypt-super merge=crypt-super' >> .gitattributes
  git add .gitattributes
  git config --unset transcrypt.super.password
  echo "TOP SECRET" > top-secret

  run git add top-secret
  [ "$status" -ne 0 ]
  [ -z "$(git ls-files top-secret)" ]
}

@test "fail-safe: clean encrypts plaintext that merely starts like ciphertext" {
  echo '"secret.env" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  printf 'U2FsdGVkX1 is how it starts\nSECRET=1\n' > secret.env
  git add .gitattributes secret.env
  git commit -q -m "Add secret"

  [ "$(git show HEAD:secret.env --no-textconv)" != "$(cat secret.env)" ]
  rm secret.env
  git checkout -- secret.env
  [ "$(cat secret.env)" = "$(printf 'U2FsdGVkX1 is how it starts\nSECRET=1')" ]
}

@test "fail-safe: clean passes through ciphertext that decrypts with the password" {
  encrypt_named_file sensitive_file "My secret content"
  git show HEAD:sensitive_file --no-textconv > sensitive_file

  run git add sensitive_file
  [ "$status" -eq 0 ]
  [ "$(git rev-parse :sensitive_file)" = "$(git rev-parse HEAD:sensitive_file)" ]
}

@test "fail-safe: ECB and non-ciphers are refused" {
  "$TRANSCRYPT" --flush-credentials --yes > /dev/null

  run "$TRANSCRYPT" --cipher=aes-256-ecb --password=pw --yes
  [ "$status" -eq 1 ]
  [[ "$output" == *'"aes-256-ecb" is not allowed'* ]]

  run "$TRANSCRYPT" --cipher=base64 --password=pw --yes
  [ "$status" -eq 1 ]
  [ -z "$(git config --get transcrypt.cipher)" ]
}

@test "fail-safe: an openssl path containing spaces still produces decryptable ciphertext" {
  mkdir "$BATS_TEST_TMPDIR/open ssl"
  ln -s "$(command -v openssl)" "$BATS_TEST_TMPDIR/open ssl/openssl"
  git config transcrypt.openssl-path "$BATS_TEST_TMPDIR/open ssl/openssl"
  encrypt_named_file sensitive_file "My secret content"

  [[ "$(git show HEAD:sensitive_file --no-textconv)" == U2FsdGVk* ]]
  rm sensitive_file
  git checkout -- sensitive_file
  [ "$(cat sensitive_file)" = "My secret content" ]
}

@test "fail-safe: clean refuses to store a file when openssl can't run" {
  echo '"secret.env" filter=crypt diff=crypt merge=crypt' >> .gitattributes
  git add .gitattributes
  git config transcrypt.openssl-path /nonexistent/openssl
  echo "SECRET=1" > secret.env

  run git add secret.env
  [ "$status" -ne 0 ]
  [ -z "$(git ls-files secret.env)" ]
}

#!/usr/bin/env bash
set -e
set -o pipefail

# Check for uncommited changes
[ -z "$(git status --porcelain)" ] || { echo "Uncommited changes"; exit 1; }

# Setup major/minor variables
major=$(grep '#define VER_MAJOR' drvperf.c | awk '{print $3}')
minor=$(grep '#define VER_MINOR' drvperf.c | awk '{print $3}')
[[ "$major" =~ [0-9]+ ]] && [[ "$minor" =~ [0-9]+ ]] || { echo 'Bad version'; exit 1; }
minor=$(($minor + 1))
echo "New version: v${major}.${minor}"

# Setup date variables
unix=$(date "+%s")
year=$(LC_ALL=C date --date="@${unix}" "+%Y")
month=$(LC_ALL=C date --date="@${unix}" "+%B")
rfc2822=$(date --date="@${unix}" -R)
echo "New timestamp: $month $year"

# Setup credentials variables
user=$(git config --get user.name)
email=$(git config --get user.email)

# Create and edit changelog
changelog=$(tempfile -s '.changelog')
{
  echo "drvperf (${major}.${minor}-1) unstable; urgency=medium"
  echo
  echo '  * EDIT ME'
  echo
  echo " -- ${user} <${email}>  ${rfc2822}"
  echo
  cat debian/changelog
} > "${changelog}"
sum1=$(md5sum "${changelog}" | awk '{print $1}')
vi "${changelog}"
sum2=$(md5sum "${changelog}" | awk '{print $1}')
[ "${sum1}" == "${sum2}" ] && { echo "No changelog provided"; rm -f ${changelog}; exit 1; }
unset sum1
unset sum2

# Update everything
mv ${changelog} debian/changelog
sed -r -i 's/^#define VER_DATE.*$/#define VER_DATE "'$month' '$year'"/' drvperf.c
sed -r -i 's/^#define VER_MINOR.*$/#define VER_MINOR '$minor'/' drvperf.c
sed -r -i 's/^\.TH drvperf.*$/.TH drvperf 1 "'$month' '$year'" "drvperf\/'$major'.'$minor'"/' drvperf.1
grep -E '^#define VER_MAJOR '$major'$' drvperf.c > /dev/null || { echo 'Patch failed (VER_MAJOR)'; exit 1; }
grep -E '^#define VER_MINOR '$minor'$' drvperf.c > /dev/null || { echo 'Patch failed (VER_MINOR)'; exit 1; }
grep -E '^\.TH drvperf 1 "'$month' '$year'" "drvperf/'$major'\.'$minor'"$' drvperf.1 > /dev/null || { echo 'Patch failed (manpage)'; exit 1; }

# Commit
echo "Committing ..."; sleep 5
git commit -a -m "Updated version to ${major}.${minor} (auto)"


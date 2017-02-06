#!/usr/bin/env bash
set -e
set -o pipefail

major=$(grep '#define VER_MAJOR' drvperf.c | awk '{print $3}')
minor=$(grep '#define VER_MINOR' drvperf.c | awk '{print $3}')
[[ "$major" =~ [0-9]+ ]] && [[ "$minor" =~ [0-9]+ ]] || { echo 'Bad version'; exit 1; }
minor=$(($minor + 1))
echo "New version: v${major}.${minor}"

year=$(LC_ALL=C date "+%Y")
month=$(LC_ALL=C date "+%B")
echo "New timestamp: $month $year"

sed -r -i 's/^#define VER_DATE.*$/#define VER_DATE "'$month' '$year'"/' drvperf.c
sed -r -i 's/^#define VER_MINOR.*$/#define VER_MINOR '$minor'/' drvperf.c
sed -r -i 's/^\.TH drvperf.*$/.TH drvperf 1 "'$month' '$year'" "drvperf\/'$major'.'$minor'"/' drvperf.1
grep -E '^#define VER_MAJOR '$major'$' drvperf.c > /dev/null || { echo 'Patch failed (VER_MAJOR)'; exit 1; }
grep -E '^#define VER_MINOR '$minor'$' drvperf.c > /dev/null || { echo 'Patch failed (VER_MINOR)'; exit 1; }
grep -E '^\.TH drvperf 1 "'$month' '$year'" "drvperf/'$major'\.'$minor'"$' drvperf.1 > /dev/null || { echo 'Patch failed (manpage)'; exit 1; }

echo "Committing ..."; sleep 5
git commit -a -m "Updated version to ${major}.${minor} (auto)"
git push


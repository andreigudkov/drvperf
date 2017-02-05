#!/usr/bin/env bash
set -e
set -o pipefail

url=$(svn info | grep -e '^URL:' | awk '{print $2}')
major=''
minor=''
year=''
month=''

# Checkout, increment version and commit back. Sets version variables.
function incversion() {
  rm -Rf tmp

  svn co "$url" tmp

  major=$(grep '#define VER_MAJOR' tmp/drvperf.c | awk '{print $3}')
  minor=$(grep '#define VER_MINOR' tmp/drvperf.c | awk '{print $3}')
  [[ "$major" =~ [0-9]+ ]] && [[ "$minor" =~ [0-9]+ ]] || { echo 'Bad version'; exit 1; }
  minor=$(($minor + 1))
  echo "New version: ${major}.${minor}"

  year=$(LC_ALL=C date "+%Y")
  month=$(LC_ALL=C date "+%B")
  echo "New timestamp: $month $year"

  sed -r -i 's/^#define VER_DATE.*$/#define VER_DATE "'$month' '$year'"/' tmp/drvperf.c
  sed -r -i 's/^#define VER_MINOR.*$/#define VER_MINOR '$minor'/' tmp/drvperf.c
  sed -r -i 's/^\.TH drvperf.*$/.TH drvperf 1 "'$month' '$year'" "drvperf\/'$major'.'$minor'"/' tmp/drvperf.1
  sed -r -i 's/\(v\)/('$major'.'$minor')/' tmp/README
  grep -E '^#define VER_MAJOR '$major'$' tmp/drvperf.c > /dev/null || { echo 'Patch failed (VER_MAJOR)'; exit 1; }
  grep -E '^#define VER_MINOR '$minor'$' tmp/drvperf.c > /dev/null || { echo 'Patch failed (VER_MINOR)'; exit 1; }
  grep -E '^\.TH drvperf 1 "'$month' '$year'" "drvperf/'$major'\.'$minor'"$' tmp/drvperf.1 > /dev/null || { echo 'Patch failed (manpage)'; exit 1; }
  grep -E '\('$major'\.'$minor'\)' tmp/README > /dev/null || { echo 'Patch README failed (empty changelog)'; exit 1; }

  echo "Committing ..."; sleep 5
  svn commit -m "Updated version to ${major}.${minor} (auto)" tmp

  rm -Rf tmp
}

function mktarball() {
  rm -Rf tmp
  mkdir tmp
  cd tmp

  svn export "$url" drvperf
  rm -Rf drvperf/releases
  mv drvperf drvperf-${major}.${minor}
  tar -cvf drvperf-${major}.${minor}.tar drvperf-${major}.${minor}
  gzip drvperf-${major}.${minor}.tar

  svn co "$url"/releases
  mv drvperf-${major}.${minor}.tar.gz releases/
  svn add releases/drvperf-${major}.${minor}.tar.gz

  echo "Committing ..."; sleep 5
  svn commit -m "Added new release ${major}.${minor} (auto)" releases

  cd ..
  rm -Rf tmp
}

incversion
mktarball
svn up


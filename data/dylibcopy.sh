#! /bin/sh

set -e

bundle="$1"

if [ ! -d "$bundle" ]; then
  echo "$bundle is not an application bundle"
  exit 1
fi

frameworks="${bundle}/Contents/Frameworks" 

mkdir -p "$frameworks"
rm -f ${frameworks}/*.processed


process_dylib()
{
  file="$1"
  dylib="$2"
  name=${dylib##*/}

  if [ ! -f "${frameworks}/$name" ] && [ ! -f "${frameworks}/$name.processed" ]; then
    touch "${frameworks}/$name.processed"
    if [ -f "$dylib" ]; then
      echo "Found dependency $name"
      cp "$dylib" "${frameworks}/$name"
    else
      echo "Dependency $name not found"
      exit 1
    fi
  fi

  install_name_tool -change "$dylib" "@executable_path/../Frameworks/$name" "$file"
}

process_dylibs()
{
  file="$1"
  while [ ! -z "$2" ]; do
    process_dylib "$file" "$2"
    shift
  done
}

for file in "${bundle}/Contents/MacOS/"*; do
  process_dylibs $file `otool -L "$file" | grep 'dylib' | sed 's/^[[:blank:]]*//' | sed 's/ .*//' | grep -v '^/usr/\|^/System/'`
done

rm -f ${frameworks}/*.processed

echo Dependencies copied

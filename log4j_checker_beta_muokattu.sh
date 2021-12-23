#!/bin/bash

# source https://github.com/rubo77/log4j_checker_beta

# needs locate to be installed, be sure to be up-to-date with
# sudo updatedb

# regular expression, check the following packages:
PACKAGES='solr\|elastic\|log4j'

# Set this if you have a download for sha256 hashes
SHA256_HASHES_URL="$1"

#RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"
# if you don't want colored output, set the variables to empty strings:
RED=""; GREEN=""; YELLOW=""; ENDCOLOR=""

function warning() {
  printf "${RED}[WARNING] %s${ENDCOLOR}\n" "$1" >&2
}

function information() {
  printf "${YELLOW}[INFO] %s${ENDCOLOR}\n" "$1"
}

function ok() {
  printf "${GREEN}[INFO] %s${ENDCOLOR}\n" "$1"
}

if [ "$SHA256_HASHES_URL" = "" ]; then
  # information "using default hash file. If you want to use other hashes, set another URL as first argument"
  SHA256_HASHES_URL="https://raw.githubusercontent.com/rubo77/log4j_checker_beta/main/hashes-pre-cve.txt"
fi

export LANG=

function locate_log4j() {
  if [ "$(command -v locate)" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      # Mac OSX
      locate -i log4j
    else
      locate -ei log4j
    fi
  else
    find \
      /var /etc /usr /opt /lib* \
      -iname "*log4j*" 2>&1 \
      | grep -v '^find:.* Permission denied$' \
      | grep -v '^find:.* No such file or directory$'
  fi
}

function find_jar_files() {
  find \
    /var /etc /usr /opt /lib* \
    -iname "*.jar" -o -iname "*.war" -o -iname "*.ear" 2>&1 \
    | grep -v '^find:.* Permission denied$' \
    | grep -v '^find:.* No such file or directory$'
}

# print hostname to stdout
echo "hostname: $(hostname)" 
# hostname 
echo ""
# print operating system information to stdout

if [ -s /etc/redhat-release ]; then
  cat /etc/redhat-release
elif [ -s /etc/lsb-release ]; then
  cat /etc/lsb-release
fi
echo ""
# print interface ip address information to stdout

if [ "$(command -v ifconfig)" ]; then
  ifconfig
elif ["$(command -v ip)"]; then
  ip address
else
  echo "IP information can't be printed."
fi
echo ""
# check root user
if [ $USER != root ]; then
  warning "You have no root-rights. Not all files will be found."
fi

dir_temp_hashes=$(mktemp -d --suffix _log4jscan)
file_temp_hashes="$dir_temp_hashes/vulnerable.hashes"
ok_hashes=
# if [[ -n $SHA256_HASHES_URL && $(command -v wget) ]]; then
#  wget  --max-redirect=0 --tries=2 -O "$file_temp_hashes.in" -- "$SHA256_HASHES_URL"
#elif [[ -n $SHA256_HASHES_URL && $(command -v curl) ]]; then
#  curl --globoff -f "$SHA256_HASHES_URL" -o "$file_temp_hashes.in"
#fi
#if [ -s hashes-pre-cve.txt ]
#then
     #echo "Hash File not empty"
     #cat hashes-prev-cve.txt > "$file_temp_hashes.in"
     #"$file_temp_hashes.in"=$(cat "hashes-prev-cve.txt")
#else
     #echo "Hash File empty"
#fi

if [[ $? = 0 && -s "hashes-prev-cve.txt" ]]; then
  cat "hashes-prev-cve.txt" | cut -d" " -f1 | sort | uniq  > "$file_temp_hashes"
  ok_hashes=1
  information "Downloaded vulnerable hashes from $SHA256_HASHES_URL"
fi

# first scan: use locate
echo
information "Looking for files containing log4j..."
if [ "$(command -v locate)" ]; then
  information "using locate, which could be using outdated data. besure to have called updatedb recently"
fi
OUTPUT="$(locate_log4j | grep -iv log4js | grep -v log4j_checker_beta)"
if [ "$OUTPUT" ]; then
  warning "Maybe vulnerable, those files contain the name:"
  printf "%s\n" "$OUTPUT"
else
  ok "No files containing log4j"
fi

# second scan: use package manager
echo
information "Checking installed packages: ($PACKAGES)"
if [ "$(command -v yum)" ]; then
  # using yum
  OUTPUT="$(yum list installed | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, yum installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No yum packages found"
  fi
fi
if [ "$(command -v dpkg)" ]; then
  # using dpkg
  OUTPUT="$(dpkg -l | grep -i $PACKAGES | grep -iv log4js)"
  if [ "$OUTPUT" ]; then
    warning "Maybe vulnerable, dpkg installed packages:"
    printf "%s\n" "$OUTPUT"
  else
    ok "No dpkg packages found"
  fi
fi

# third scan: check for "java" command
echo
information "Checking if Java is installed..."
JAVA="$(command -v java)"
if [ "$JAVA" ]; then
  warning "Java is installed"
  printf "     %s\n     %s\n" \
    "Java applications often bundle their libraries inside binary files," \
    "so there could be log4j in such applications."
else
  ok "Java is not installed"
fi

# perform best-effort find call for all jars and optionally check against hashes
echo
information "Analyzing JAR/WAR/EAR files..."
if [ $ok_hashes ]; then
  information "Also checking hashes"
fi
if [ "$(command -v unzip)" ]; then
  find_jar_files | while read -r jar_file; do
    unzip -l "$jar_file" 2> /dev/null \
      | grep -q -i "log4j" \
      && warning "contains log4j files: $jar_file"
    if [ $ok_hashes ]; then
      base_name=$(basename "$jar_file")
      dir_unzip="$dir_temp_hashes/java/$( echo "$base_name" | tr -dc '[[:alpha:]]')_$(hexdump -v -n 3 -e '1/1 "%02x"' </dev/urandom)"
      mkdir -p "$dir_unzip"
      unzip -qq -DD "$jar_file" '*.class' -d "$dir_unzip" 2> /dev/null \
        && find "$dir_unzip" -type f -not -name "*"$'\n'"*" -iname '*.class' -exec sha256sum "{}" \; \
        | cut -d" " -f1 | sort | uniq > "$dir_unzip/$base_name.hashes";
      if [ -f "$dir_unzip/$base_name.hashes" ]; then
        num_found=$(comm -12 "$file_temp_hashes" "$dir_unzip/$base_name.hashes" | wc -l)
      else
        num_found=0
      fi
      if [[ -n $num_found && $num_found != 0 ]]; then
        warning "vulnerable binary classes in: $jar_file"
      else
        ok "No .class files with known vulnerable hash found in $jar_file at first level."
      fi
      # delete temp folder containing the extracted java files
      rm -rf -- "$dir_unzip"
    fi
  done
else
  information "Cannot look for log4j inside JAR/WAR/EAR files (unzip not found)"
fi

# delete temp folder containing $file_temp_hashes
[ $ok_hashes ] && rm -rf -- "$dir_temp_hashes"

information "_________________________________________________"
if [ "$JAVA" == "" ]; then
  warning "Some apps bundle the vulnerable library in their own compiled package, so even if 'java' is not installed, one of the applications could still be vulnerable."
fi

echo
warning "This script does not guarantee that you are not vulnerable, but is a strong hint."
echo

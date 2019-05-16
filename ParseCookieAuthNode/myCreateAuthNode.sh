#!/bin/bash
# set -x

DATE="`date +%Y%m%d-%H%M`"

count="`find . -type f -name '*Plugin.java' -exec grep -c 'static private String currentVersion = ' {} \;`"
if [ ${count} -eq 1 ]; then
  pfile="`find . -type f -name '*Plugin.java' -exec grep -l 'static private String currentVersion = ' {} \;`"
else
  echo "no PluginFile found; exiting!"
  exit 1
fi
cur_ver="`grep \"static private String currentVersion = \" ${pfile} | awk -F"\\"" '{ print $2 }'`"

if [ "x${cur_ver}" != "x" ]; then
  echo "Current version is set to '${cur_ver}'."
  read -p "Do you wan to keep it? (y/n)" ANS
  case ${ANS} in
    y|yes|j|ja)
      ver=${cur_ver}
      ;;
    n|no|nein)
      read -p "Please provide new version string:" ANS2
      new_ver="${ANS2}"
      change_ver="yes"
      ;;
    *)
      echo "No valid answer; exiting!"
      exit 1
    ;;
  esac
else
  echo "Cannot extract current version; exiting!"
  exit 1
fi

if [ "${change_ver}" = "yes" ]; then
  mv ${pfile} ${pfile}.${DATE}
  cat ${pfile}.${DATE} | sed -e s/${cur_ver}/${new_ver}/g > ${pfile}
fi

echo "Creating clean target ..."
mvn clean install
RES=$?

if [ ${RES} -eq 0 ]; then
  echo "done."
else
  echo "An error occured, please check output."
fi

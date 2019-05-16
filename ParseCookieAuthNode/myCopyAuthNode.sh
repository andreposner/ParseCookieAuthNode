#!/bin/bash
# set -x

DATE="`date +%Y%m%d-%H%M`"

SRC_PATH="./target"
DST_USR="forgerock"
# DST_HOST="18.194.208.236"
DST_HOST="login.openrock.org"
DST_PATH="~/tomcat8.5/webapps/openam/WEB-INF/lib"

MODULE_NAME="ParseCookieAuthNode-1.0.0-SNAPSHOT.jar"

scp -i ~/.ssh/andre_aws.pem ${SRC_PATH}/${MODULE_NAME} ${DST_USR}@${DST_HOST}:${DST_PATH}
ssh -i ~/.ssh/andre_aws.pem ${DST_USR}@${DST_HOST} "cd ${DST_PATH} && chmod 640 ${MODULE_NAME}"


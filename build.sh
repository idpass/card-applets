#!/bin/sh
#

export JC_HOME=$(pwd)/libs-sdks/jc304_kit/
export _JAVA_OPTIONS=-Djc.home=$JC_HOME

buildoutputs='
build/javacard/auth.cap
build/javacard/tools.exp/org/idpass/tools/javacard/tools.cap
build/javacard/sam.cap
build/javacard/datastorage.cap
build/libs/idpass_tools.jar
build/libs/idpass_auth.jar
build/libs/idpass_datastorage.jar
build/libs/idpass_sam.jar'

buildoutputscount=$(echo $buildoutputs | tr ' ' '\n' | wc -l)
./gradlew build

count=0
for x in $buildoutputs;do
    if [ ! -f $x ];then
        echo "Failed to build $x"
        continue
    fi
    count=$((count+1))
done

[ "$count" -eq "$buildoutputscount" ] && return 0 || return 1


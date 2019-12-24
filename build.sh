#!/bin/sh
#

export JC_HOME=$(pwd)/libs-sdks/jc304_kit/
export _JAVA_OPTIONS=-Djc.home=$JC_HOME

buildoutputs='
build/javacard/org/idpass/auth/javacard/auth.cap
build/javacard/org/idpass/tools/javacard/tools.cap
build/javacard/org/idpass/sam/javacard/sam.cap
build/javacard/org/idpass/datastorage/javacard/datastorage.cap'

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


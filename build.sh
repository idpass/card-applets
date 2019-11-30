#!/bin/sh
#

export JC_HOME=$(pwd)/libs-sdks/jc304_kit/
export _JAVA_OPTIONS=-Djc.home=$JC_HOME

./gradlew build

echo
echo "*** Generated *.cap files ***"
find build -type f -name '*.cap' -exec wc -c {} \;
echo

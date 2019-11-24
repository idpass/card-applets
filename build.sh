#!/bin/sh
#

echo "*** environment check ***"
git branch
echo */
ls
#find . -type f -name '*.java'
echo "----------oOo---------"

export JC_HOME=$(pwd)/libs-sdks/jc304_kit/
export _JAVA_OPTIONS=-Djc.home=$JC_HOME

rm -rf build/

./gradlew -b build.gradle.tools build
./gradlew -b build.gradle.auth convertJavacard
./gradlew -b build.gradle.sam convertJavacard

echo
echo "*** Generated *.cap files ***"
find build -type f -name '*.cap' -exec wc -c {} \;
echo

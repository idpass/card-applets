#!/bin/sh
#

if [ $(git branch | grep \* | cut -d ' ' -f2) = "master" ];then
    echo "For nown, only build the branches"   
    return
fi

echo "Building branch now ..."

if [ ! -d libs-sdks ];then
    git clone https://github.com/martinpaljak/oracle_javacard_sdks.git libs-sdks
fi

mkdir -p src/main/java/org/idpass

find . -type f -name '*.java'

ln -sf `pwd`/tools/src/org/idpass/tools `pwd`/src/main/java/org/idpass/
ln -sf `pwd`/auth/src/org/idpass/auth `pwd`/src/main/java/org/idpass/
ln -sf `pwd`/sam/src/org/idpass/sam `pwd`/src/main/java/org/idpass/

make

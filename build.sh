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

t=tmp$$
mkdir -p $t
git clone git@github.com:idpass/card-tools-applet.git $t/tools
git clone git@github.com:idpass/card-auth-applet.git $t/auth
git clone git@github.com:idpass/card-sam-applet.git $t/sam

ln -sf `pwd`/$t/tools/src/org/idpass/tools `pwd`/src/main/java/org/idpass/
ln -sf `pwd`/$t/auth/src/org/idpass/auth `pwd`/src/main/java/org/idpass/
ln -sf `pwd`/$t/sam/src/org/idpass/sam `pwd`/src/main/java/org/idpass/

make

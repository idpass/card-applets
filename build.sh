#!/bin/sh
#

t=$(pwd)/tmp$$
mkdir -p $t/src/main/java/org/idpass/

echo "[$t]"
for x in tools auth sam;do
    ln -sf `pwd`/src/main/java/org/idpass/$x/src/org/idpass/$x/ $t/src/main/java/org/idpass/
done

export t
make
rm -rf $t

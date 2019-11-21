#!/bin/sh
#

if [ $# -lt 2 ];then
    echo "Usage:"
    echo "./convert.sh org.app.test <packageid> [appletid]"
    echo "TIP: Convert first org.idpass.tools because it is the base package"
    return
fi

otherlibs=libs
sdks=libs-sdks
jckit=jc304_kit
JC_HOME=$sdks/$jckit/

classpath=\
$sdks/$jckit/lib/api_classic.jar:\
$sdks/$jckit/lib/tools.jar:\
$sdks/$jckit/lib/jctasks.jar:\
$sdks/$jckit/lib/commons-logging-1.1.jar:\
$sdks/$jckit/lib/commons-httpclient-3.0.jar:\
$sdks/$jckit/lib/commons-codec-1.3.jar:\
$sdks/$jckit/lib/commons-cli-1.0.jar:\
$sdks/$jckit/lib/bcel-5.2.jar:\
$sdks/$jckit/lib/asm-all-3.1.jar:\
$sdks/$jckit/lib/api_classic_annotations.jar:\
$sdks/$jckit/lib/ant-contrib-1.0b3.jar

outdir=build/
exportpath=$sdks/jc222_kit:$otherlibs/globalplatform-2_1_1:$sdks/$jckit/api_export_files:$outdir
version=1.0

packagename=$1
pkgid=$2

if [ $# -eq 4 ];then
    appletid=$3
    appletMain=$4
    java -Djc.home=$JC_HOME \
        -classpath $classpath \
        com.sun.javacard.converter.Main \
    	-v \
            -d $outdir \
            -classdir $outdir \
            -noverify \
            -out CAP EXP JCA \
            -exportpath $exportpath \
    	    -useproxyclass $packagename $pkgid $version \
    	    -applet $appletid $appletMain
else
    java -Djc.home=$JC_HOME \
        -classpath $classpath \
        com.sun.javacard.converter.Main \
    	-v \
            -d $outdir \
            -classdir $outdir \
            -noverify \
            -out CAP EXP JCA \
            -exportpath $exportpath \
            -useproxyclass $packagename $pkgid $version
fi

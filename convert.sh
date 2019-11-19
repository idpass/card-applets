#!/bin/sh
#

if [ $# -ne 2 ];then
    echo "Usage:"
    echo "./convert.sh org.idpass.tools 0xf7:0x69:0x64:0x70:0x61:0x73:0x73:0x0"
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

packagename=$1
pkgid=$2

version=1.0

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

#!/bin/bash
#

# Description: This script is meant to be sourced from the bash command line
# to formalize repeatitive commands from the terminal. This only works in bash.

export JC_HOME=$(pwd)/libs-sdks/jc304_kit/
export _JAVA_OPTIONS="-Djc.home=$JC_HOME $_JAVA_OPTIONS"

findgradles() {
    local x
    [ $# -eq 0 ] && x=. || x=$1
    find $x -type f \( -name '*.gradle' -o -name 'gradle.properties' \)
}

findcap() {
    local x
    [ $# -eq 0 ] && x=. || x=$1
    find $x -type f -name '*.cap'
}

findjar() {
    local x
    [ $# -eq 0 ] && x=. || x=$1
    find $x -type f -name '*.jar'
}

findclass() {
    local x
    [ $# -eq 0 ] && x=. || x=$1
    find $x -type f -name '*.class'
}

findexp() {
    local x
    [ $# -eq 0 ] && x=. || x=$1
    find $x -type f -name '*.exp'
}

findjava() {
    local x
    [ $# -eq 0 ] && x=. || x=$1
    find $x -type f -name '*.java'
}

findjavawith() {
    [ $# -eq 0 ] && return
    local x
    local y
    if [ $# -eq 1 ];then
        x=. 
        y=$1
    else
        x=$1
        y=$2
    fi
    find $x -type f -name '*.java' -exec grep -q -w $y {} \; -exec echo {} \;
}

# This is for piping and items stored into (named) bash array
# for later quick retrieval. It stores the named arrays into the
# idx file just for mnemonics. Piping with iii must then be followed 
# by _ to either assigned into the default x variable or to any
# supplied variable name
iii () { 
    local f=/tmp/pathfinder
    local t=$(</dev/stdin);
    echo "$t" > $f;
    nl -v 0 -ba $f
}

_ () 
{ 
    if [ $# -eq 0 ]; then
        x=($(</tmp/pathfinder));
    else
        local var=$1;
        eval "${var}=($(</tmp/pathfinder))";
        echo $var >> idx;
    fi
}

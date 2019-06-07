#!/bin/bash

# tested on Ubuntu 18.04 x64
echo "usage:
# bash run.sh [-env, -i]
# -env: create virtual environment"

export VENV="venv"

if [ $1 ]; then
    # install env
    if [ $1 == "-env" ]; then
         echo "*** INSTALL ENV ***"
         virtualenv -p python3 $VENV

    else
        echo "*** START ***"
        $VENV/bin/python3 $1
        echo "*** STOP ***"
    fi
fi

# start repl
if [ -z $1 ]; then
    echo "*** START ***"
    $VENV/bin/python3
    echo "*** STOP ***"
fi

echo "*** THE END ***"

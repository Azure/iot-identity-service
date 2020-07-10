#!/bin/bash

cd /src

. ./ci/install-build-deps.sh


case "$CONTAINER_OS" in
    'centos:7')
        MAKE_VARS=''
        ;;

    'debian:9-slim')
        MAKE_VARS=''
        ;;

    'debian:10-slim')
        MAKE_VARS=''
        ;;

    *)
        exit 1
esac


make V=1 $MAKE_VARS test

#!/bin/bash

pkg=$1
if [[ "$pkg" == "" ]]; then
pkg='*'
fi

$(dirname $0)/check_app.sh "$pkg"
$(dirname $0)/check_common.sh "$pkg"
$(dirname $0)/check_thirdparty.sh "$pkg"

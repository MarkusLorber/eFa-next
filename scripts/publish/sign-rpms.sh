#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# On the build host, in the background: rpmsign with gpg-relay in place of gpg. sign.done holds its exit code at the end.
W=$1
FPR=$2
cd "$W" || exit 1
rpmsign --define "__gpg $W/gpg-relay" --define "_gpg_name $FPR" --addsign out/*.rpm > sign.log 2>&1
echo $? > sign.done

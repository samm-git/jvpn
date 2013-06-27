#!/bin/sh

# RSA software token (stoken) password helper
# see https://github.com/cernekee/stoken/ for the details

if [ -n "$OLDPIN" ]
then
    PIN=`stoken`
    while [ "$OLDPIN" = "$PIN" ]
    do
	PIN=`stoken --batch`
	sleep 1
    done
    echo $PIN;
else
    # new pin requested
    stoken --batch
fi
# wait 1 second before return
sleep 1
#!/bin/bash

if test $# -ne 1; then
    echo "Usage: check-mount.sh {START|FILL|CLEAN|CHECK}"
    exit 2
fi

function umount_akt () {
	umount regtests/result/mount 2>/dev/null
}

case $1 in
    START)
        rm -rf regtests/result/mount
        mkdir -p regtests/result/mount &&
        bin/akt create regtests/result/test-mount.akt --password=mount -c 100:1000 -f &&
        echo "PASS"
        res=$?
        ;;

    FILL)
        trap umount_akt 0
        bin/akt mount --password=mount regtests/result/test-mount.akt regtests/result/mount &&
        sleep 1 &&
        cp -r obj regtests/result/mount &&
        diff -rup obj regtests/result/mount/obj &&
        cp -r src regtests/result/mount &&
        diff -rup src regtests/result/mount/src &&
        echo "PASS"
        res=$?
        ;;

    CLEAN)
        trap umount_akt 0
        bin/akt mount -f --password=mount regtests/result/test-mount.akt regtests/result/mount &
        sleep 1
        rm -rf regtests/result/mount/obj &&
        rm -rf regtests/result/mount/src &&
        cp configure LICENSE.txt regtests/result/mount/ &&
        diff -rup LICENSE.txt regtests/result/mount/ &&
        echo "PASS"
        res=$?
        ;;

    BIG)
        trap umount_akt 0
        bin/akt mount -f --password=mount regtests/result/test-mount.akt regtests/result/mount &
        sleep 1
        for i in 1 2 3 ; do
            rm -rf regtests/result/mount/bin &&
            cp -r bin regtests/result/mount/bin &&
            diff -r bin regtests/result/mount/bin &&
            cp configure LICENSE.txt regtests/result/mount/ &&
            diff -rup LICENSE.txt regtests/result/mount/
        done
        echo "PASS"
        res=$?
        ;;

    MIX)
        trap umount_akt 0
        bin/akt mount -f --password=mount regtests/result/test-mount.akt regtests/result/mount &
        sleep 1
        for i in 1 2 3 4 5; do
            rm -rf regtests/result/mount/bin &&
            cp -r bin regtests/result/mount/bin &&
            diff -r bin regtests/result/mount/bin &&
            rm -rf regtests/result/mount/obj &&
            cp -r obj regtests/result/mount/obj &&
            diff -r obj regtests/result/mount/obj &&
            cp configure LICENSE.txt regtests/result/mount/ &&
            diff -rup LICENSE.txt regtests/result/mount/
        done
        echo "PASS"
        res=$?
        ;;

    CHECK)
        bin/akt list --password=mount regtests/result/test-mount.akt > /dev/null &&
        bin/akt get -n --password=mount regtests/result/test-mount.akt LICENSE.txt > regtests/result/LICENSE.txt &&
        cmp LICENSE.txt regtests/result/LICENSE.txt
        echo "PASS"
        res=$?
        ;;

    *)
        exit 1;
        ;;
esac

exit $res

#!/bin/bash
AKT=akt/bin/akt

if test $# -ne 1; then
    echo "Usage: check-mount.sh {START|FILL|CLEAN|CHECK}"
    exit 2
fi

function umount_akt () {
	umount regtests/results/mount 2>/dev/null
}

case $1 in
    START)
        rm -rf regtests/results/mount
        mkdir -p regtests/results/mount &&
        ${AKT} create regtests/results/test-mount.akt --password=mount -c 100:1000 -f &&
        echo "PASS"
        res=$?
        ;;

    FILL)
        trap umount_akt 0
        ${AKT} mount --password=mount regtests/results/test-mount.akt regtests/results/mount &&
        sleep 1 &&
        cp -r obj regtests/results/mount &&
        diff -rup obj regtests/results/mount/obj &&
        cp -r src regtests/results/mount &&
        diff -rup src regtests/results/mount/src &&
        echo "PASS"
        res=$?
        ;;

    CLEAN)
        trap umount_akt 0
        ${AKT} mount -f --password=mount regtests/results/test-mount.akt regtests/results/mount &
        sleep 1
        rm -rf regtests/results/mount/obj &&
        rm -rf regtests/results/mount/src &&
        cp src/*.ad? LICENSE.txt regtests/results/mount/ &&
        diff -rup LICENSE.txt regtests/results/mount/ &&
        echo "PASS"
        res=$?
        ;;

    BIG)
        trap umount_akt 0
        ${AKT} mount -f --password=mount regtests/results/test-mount.akt regtests/results/mount &
        sleep 1
        for i in 1 2 3 ; do
            rm -rf regtests/results/mount/bin &&
            cp -r bin regtests/results/mount/bin &&
            diff -r bin regtests/results/mount/bin &&
            cp src/*.ad? LICENSE.txt regtests/results/mount/ &&
            diff -rup LICENSE.txt regtests/results/mount/
        done
        echo "PASS"
        res=$?
        ;;

    MIX)
        trap umount_akt 0
        ${AKT} mount -f --password=mount regtests/results/test-mount.akt regtests/results/mount &
        sleep 1
        for i in 1 2 3 4 5; do
            rm -rf regtests/results/mount/bin &&
            cp -r bin regtests/results/mount/bin &&
            diff -r bin regtests/results/mount/bin &&
            rm -rf regtests/results/mount/obj &&
            cp -r obj regtests/results/mount/obj &&
            diff -r obj regtests/results/mount/obj &&
            cp src/*.ad? LICENSE.txt regtests/results/mount/ &&
            diff -rup LICENSE.txt regtests/results/mount/
        done
        echo "PASS"
        res=$?
        ;;

    CHECK)
        ${AKT} list --password=mount regtests/results/test-mount.akt > /dev/null &&
        ${AKT} get -n --password=mount regtests/results/test-mount.akt LICENSE.txt > regtests/results/LICENSE.txt &&
        cmp LICENSE.txt regtests/results/LICENSE.txt
        echo "PASS"
        res=$?
        ;;

    *)
        exit 1;
        ;;
esac

exit $res

#!/usr/bin/env bash

cd $(dirname $0)
NSS_DIR=${NSS_DIR:-../nss}
DIST_DIR="$NSS_DIR/../dist/$(cat $NSS_DIR/../dist/latest)"
SSL_GTEST="${SSL_GTEST:-${DIST_DIR}/bin/ssl_gtest}"
DB_DIR="${DB_DIR:-ssl_gtests}"

declare -A tmpfiles
rmtmp() {
    rm -f "${tmpfiles[@]}" 1>&2
    #echo "Saving temporary files: ${tmpfiles[@]}" 1>&2
}
trap rmtmp EXIT
newtmp() {
    if [[ -z "$2" ]]; then
        echo /dev/null
    elif [[ -n "${tmpfiles[${1}_${2}]}" ]]; then
        echo "${tmpfiles[${1}_${2}]}"
    else
        echo $(mktemp /tmp/$(echo $1 | tr '/' '_').$2.XXXXX)
    fi
}

text=()
process() {
    i=$2
    if [[ "${i#'>>>'}" != "$i" ]]; then
        # don't quote $i here so that it splits on space
        args=(${i#'>>>'})
        tmp3=$(newtmp "${args[0]}" "${args[1]}")
        tmpfiles["${args[0]}_${args[1]}"]=$tmp3
        if [[ -n "${args[2]}" ]]; then
            tmp4=$(newtmp "${args[0]}" "${args[2]}")
            tmpfiles["${args[0]}_${args[2]}"]=$tmp4
        else
            tmp4=/dev/null
        fi
        log=$(newtmp "${args[0]}" log)
        tmpfiles["${args[0]}"]="$log"

        LD_LIBRARY_PATH="${DIST_DIR}/lib" \
                       DYLD_LIBRARY_PATH="${DIST_DIR}/lib" \
                       SSLTRACE=50 \
                       "$SSL_GTEST" -d "$DB_DIR" --gtest_filter="${args[0]}" 2>&1 | \
            tee "$log" | \
            ./processlog.py 3>"$tmp3" 4>"$tmp4"
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
    elif [[ "${i#'<<<'}" != "$i" ]]; then
        args=(${i#'<<<'})
        cat "${tmpfiles[${args[0]}_${args[1]}]}"
    else
        echo "$i"
    fi
    text=()
}
readarray -t -n 0 -C process -c 1 text <"${1:-/dev/stdin}"

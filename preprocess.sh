#!/usr/bin/env bash

cd $(dirname $0)
NSSDIR=${NSSDIR:-../nss}
DIST_DIR="$NSSDIR/../dist/$(make -s -C ../nss platform)"
SSL_GTEST="${SSL_GTEST:-${DIST_DIR}/bin/ssl_gtest}"
DB_DIR="${DB_DIR:-ssl_gtests}"

text=()
process() {
  for i in "${text[@]}"; do
    if [[ "${i##%%%}" == "$i" ]]; then
      echo -n "$i"
    else
      LD_LIBRARY_PATH="${DIST_DIR}/lib" \
        DYLD_LIBRARY_PATH="${DIST_DIR}/lib" \
        SSLTRACE=50 \
        "$SSL_GTEST" -d "$DB_DIR" --gtest_filter="$(echo ${i##%%%})" 2>&1 | \
tee -a log|        ./processlog.py
      if [[ $? -ne 0 ]]; then
        exit 1
      fi
    fi
  done
  text=()
}
readarray -n 0 -C process -c 100 text <"${1:-/dev/stdin}"


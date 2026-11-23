#!/usr/bin/env bash

set -u

API="https://stat.ripe.net/data/announced-prefixes/data.json"

jq -r '
  .data.countries[].routed
  | scan("AsnSingle\\([0-9]+\\)")
  | capture("AsnSingle\\((?<asn>[0-9]+)\\)").asn
' asns.txt |
while read -r ASN; do

    OUTPUT="${ASN}.txt"

    # Skip if the file already exists
    if [[ -f "$OUTPUT" ]]; then
        echo "Skipping AS${ASN} - ${OUTPUT} already exists"
        continue
    fi

    echo "Fetching AS${ASN}..."

    if curl -sS --fail \
        --get "$API" \
        --data-urlencode "resource=AS${ASN}" \
        --data-urlencode "min_peers_seeing=1" \
        | jq -r '.data.prefixes[]?.prefix' > "${OUTPUT}"
    then
        echo "  -> ${OUTPUT}"
    else
        echo "  ERROR fetching AS${ASN}" >&2
        rm -f "${OUTPUT}"
    fi

done

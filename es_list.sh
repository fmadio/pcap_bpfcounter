#!/usr/local/bin/bash
curl -H "Content-Type: application/json"    -XPOST "http://192.168.2.115:9200/bpfcounter_test/_search" --data-binary "@list.json" | jq


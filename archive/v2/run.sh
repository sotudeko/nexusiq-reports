#!/bin/bash

iqUrl=$1
iqUser=$2
iqPwd=$3

iqUrl=http://localhost:8070
iqUser=admin
iqPwd=admin123

rm -rf ./datafiles

python3 iq-component-overrides.py ${iqUrl} ${iqUser} ${iqPwd}
python3 iq-policyviolations-for-overrides.py ${iqUrl} ${iqUser} ${iqPwd}
python3 iq-apply-waivers-for-overrides.py

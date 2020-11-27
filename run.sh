#!/bin/bash

iqUrl=$1
iqUser=$2
iqPwd=$3

python3 iq-component-overrides-report.py ${iqUrl} ${iqUser} ${iqPwd}
python3 iq-policyviolations-for-overrides.py ${iqUrl} ${iqUser} ${iqPwd}
python3 iq-waivers-for-overrides.py

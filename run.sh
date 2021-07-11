#!/bin/bash

iqUrl=$1
iqUser=$2
iqPwd=$3

iqUrl=http://localhost:8070
iqUser=admin
iqPwd=admin123

datafiles_dir="./datafiles"
violations_dir=${datafiles_dir}/violations
license_dir=${datafiles_dir}/licensedata

rm -rf ${datafiles_dir}

mkdir ${datafiles_dir}
mkdir ${violations_dir}
mkdir ${license_dir}

python3 get-application-reports.py ${iqUrl} ${iqUser} ${iqPwd}
python3 get-security-overrides.py ${iqUrl} ${iqUser} ${iqPwd}
python3 get-security-overrides-policyinfo.py ${iqUrl} ${iqUser} ${iqPwd}

# python3 get-license-overrides.py ${iqUrl} ${iqUser} ${iqPwd}
python3 waiver-cmds.py

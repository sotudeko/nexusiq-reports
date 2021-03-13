#!/bin/bash

iqUrl=$1
iqUser=$2
iqPwd=$3

iqUrl=http://localhost:8070
iqUser=admin
iqPwd=admin123

datafiles_dir="./datafiles"
violations_dir=${datafiles_dir}/violations

rm -rf ${datafiles_dir}

mkdir ${datafiles_dir}
mkdir ${violations_dir}

python3 get-security-overrides.py ${iqUrl} ${iqUser} ${iqPwd}
python3 get-application-reports.py ${iqUrl} ${iqUser} ${iqPwd}
python3 get-violations-for-sec-overrides.py ${iqUrl} ${iqUser} ${iqPwd}

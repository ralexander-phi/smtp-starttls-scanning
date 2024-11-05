#!/bin/bash

set -e

source venv/bin/activate

MY_DOMAIN=alexsci.com
#DOMAIN_LIST=cloudflare-radar_top-1000-domains_20241028-20241104.csv
DOMAIN_LIST=short-list

DATE=$(date --iso-8601)

python check_spf.py $MY_DOMAIN

if [  -f results.db ]; then
  echo "Results already exist!"
  exit 1
fi
python manage.py migrate db

PYTHONUNBUFFERED=1 python analyze.py $DOMAIN_LIST $MY_DOMAIN 2>&1 | tee -a log-${DATE}.txt
python analyze.py 2>&1 | tee -a analysis-${DATE}.txt


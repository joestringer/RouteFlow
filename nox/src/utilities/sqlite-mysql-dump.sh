#!/bin/sh
EXPECTED_ARGS=5

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` <sqlite-filename> <msyql host> <mysql username> <mysql password> <mysql database>"
  exit 65
fi

sqlite3 $1 .dump | \
grep -v "BEGIN TRANSACTION;" | \
grep -v "COMMIT;" | \
grep -v "CREATE INDEX" | \
perl -pe 's/INSERT INTO \"(.*)\" VALUES/INSERT INTO `\1` VALUES/' | \
perl -pe 's/PRIMARY KEY//g' | \
perl -pe 's/INTEGER/BIGINT/g' | \
perl -pe 's/CREATE TABLE/CREATE TABLE IF NOT EXISTS/' | \
mysql -u $3 -p$4 -h $2 $5

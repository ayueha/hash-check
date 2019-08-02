#!/bin/bash
cd init_sql
sqlite3 ../database/init_hashmaster < init_create.sql

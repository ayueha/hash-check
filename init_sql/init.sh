#!/bin/bash
cd init_sql
sqlite3 ../database/hashmaster < init_create.sql

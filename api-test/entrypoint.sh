#!/bin/bash

## Run automationtests
exec java -Dmodules="$MODULES" -Denv.user="$ENV_USER" -Denv.endpoint="$ENV_ENDPOINT" -Denv.testLevel="$ENV_TESTLEVEL" -jar apitest-keymanager-*-jar-with-dependencies.jar
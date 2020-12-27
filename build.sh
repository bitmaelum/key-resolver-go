#!/bin/sh

docker build -t bitmaelum/bitmaelum-keyresolver:latest .
docker push bitmaelum/bitmaelum-keyresolver:latest

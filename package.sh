#!/bin/bash

apprun3-package control-app.apprunxproj -o CapturedQRAgent Controller.apprunx
apprun3-package daemon.apprunxproj -o capturedqragentd.apprunx


@echo off

:Installation-Process
title NodeJS Installation
echo Installing npm dependencies...
call npm install
echo Dependencies installed.

IF EXIST ".env" (
    REM File exists, skip this part
) ELSE (
    echo SESSION = %random% > .env
)

exit
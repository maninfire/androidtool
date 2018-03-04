@echo off
if "%PATH_BASE%" == "" set PATH_BASE=%PATH%
set PATH=%CD%;%PATH_BASE%;
copy D:\android\apktool\demo.keystore demo.keystore
pause
jarsigner -verbose -keystore demo.keystore %* demo.keystore
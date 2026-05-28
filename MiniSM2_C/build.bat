@echo off
setlocal
gcc -O2 -std=c99 -Iinclude src\bigint.c src\sm3.c src\ecc.c src\sm2.c src\util.c src\benchmark.c src\main.c -o MiniSM2.exe
if errorlevel 1 exit /b 1
echo Build success: MiniSM2.exe

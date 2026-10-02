@echo off
rem 双击即看远程节点 GUI（PowerShell 脚本负责隧道与清理）
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0asg-remote.ps1"

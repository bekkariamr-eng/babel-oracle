@echo off
title Babel Oracle
pip install cryptography --quiet >nul 2>&1
python babel_oracle.py
pause

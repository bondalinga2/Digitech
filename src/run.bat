@echo off
:: Check if Python is installed
python --version
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed. Please install Python from https://www.python.org/downloads/
    exit /b
)

:: Check if pip is installed
pip --version
IF %ERRORLEVEL% NEQ 0 (
    echo pip is not installed. Please install pip to proceed.
    exit /b
)

:: Install required Python packages
echo Installing required Python packages...
pip install flask

:: Set Flask environment variables
echo Setting Flask environment variables...
SET FLASK_APP=app.py
SET FLASK_ENV=development

:: Run the Flask app
echo Running Flask app...
python -m flask run

pause

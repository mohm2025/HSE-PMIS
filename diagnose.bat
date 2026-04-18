@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM  HSSE System Health Check — runs from project root
REM  Usage: double-click, or run from CMD:  diagnose.bat
REM ─────────────────────────────────────────────────────────────────────────────
echo.
echo ====================================================================
echo   HSSE DIAGNOSTIC REPORT - %DATE% %TIME%
echo ====================================================================
echo.

echo [1/10] Current directory
echo --------------------------------------------------------------------
cd
echo.

echo [2/10] Git commit log (last 5)
echo --------------------------------------------------------------------
git log --oneline -5 2>&1
echo.

echo [3/10] Git status
echo --------------------------------------------------------------------
git status --short 2>&1
echo.

echo [4/10] netlify.toml exists?
echo --------------------------------------------------------------------
if exist netlify.toml (
  echo [OK] netlify.toml found
  echo --- First 40 lines ---
  powershell -Command "Get-Content netlify.toml -TotalCount 40"
) else (
  echo [FAIL] netlify.toml NOT FOUND - this is why functions fail to deploy
)
echo.

echo [5/10] netlify/functions directory
echo --------------------------------------------------------------------
if exist netlify\functions (
  dir netlify\functions /b
) else (
  echo [FAIL] netlify\functions directory NOT FOUND
)
echo.

echo [6/10] netlify/functions/package.json
echo --------------------------------------------------------------------
if exist netlify\functions\package.json (
  type netlify\functions\package.json
) else (
  echo [FAIL] netlify\functions\package.json NOT FOUND
)
echo.

echo [7/10] bcryptjs installed in functions?
echo --------------------------------------------------------------------
if exist netlify\functions\node_modules\bcryptjs (
  echo [OK] bcryptjs module folder exists
) else (
  echo [FAIL] bcryptjs module NOT installed - run: cd netlify\functions ^&^& npm install
)
echo.

echo [8/10] api.js file size (should be ~39KB for v3.2)
echo --------------------------------------------------------------------
if exist netlify\functions\api.js (
  for %%I in (netlify\functions\api.js) do echo Size: %%~zI bytes
  echo --- First line ---
  powershell -Command "Get-Content netlify\functions\api.js -TotalCount 1"
) else (
  echo [FAIL] api.js NOT FOUND
)
echo.

echo [9/10] Root package.json build script
echo --------------------------------------------------------------------
if exist package.json (
  powershell -Command "(Get-Content package.json | ConvertFrom-Json).scripts | ConvertTo-Json"
) else (
  echo [FAIL] Root package.json NOT FOUND
)
echo.

echo [10/10] src/App.js has can() helper? (B1 indicator)
echo --------------------------------------------------------------------
if exist src\App.js (
  powershell -Command "if (Select-String -Path src\App.js -Pattern 'SCOPED-GRANTS PERMISSION CHECK' -Quiet) { Write-Host '[OK] B1 can() helper present' } else { Write-Host '[INFO] B1 not in App.js - pre-B1 version' }"
  powershell -Command "(Get-Content src\App.js | Measure-Object -Line).Lines" | findstr /r "^[0-9]*$"
) else (
  echo [FAIL] src\App.js NOT FOUND
)
echo.

echo ====================================================================
echo   Copy everything above this line and paste it back to Claude
echo ====================================================================
pause

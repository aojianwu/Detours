call "%VS120COMNTOOLS%..\..\VC\vcvarsall.bat" 

call nmake clean
SET DETOURS_TARGET_PROCESSOR=%1
call nmake all

IF NOT %ERRORLEVEL% == 0 (
    ENDLOCAL
	COLOR 4f
	ECHO.
	ECHO.
    ECHO [^^^^^^^^^^^^^^^^^^^^^^%DETOURS_TARGET_PROCESSOR% compile error.please check it.^^^^^^^^^^^^^^^^^^^^^^]
	ECHO.
	ECHO.
    PAUSE
    GOTO end
)

pause
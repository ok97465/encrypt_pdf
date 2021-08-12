Set oShell = CreateObject ("Wscript.Shell")
Dim strArgs
strArgs = "cmd /c c:\Users\ok974\Anaconda3\Scripts\activate&cd c:\codepy\encrypt_pdf&python.exe main.py"
oShell.Run strArgs, 0, false

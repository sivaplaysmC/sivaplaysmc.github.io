---
title: 'Docm'
date: 2024-12-09T12:13:04+05:30
draft: true
---

This challenge's statement is a lie. Just like your perception of the **w.

<!--more-->

## Statement

A challenge where the goal was to analyze a malicious DOCM file, extract the encryption key from the ransomware, and decrypt the encrypted data.

## Solution

Analysing the file

```terminal
$ file File.docm 
File.docm: Microsoft Word 2007+
```

Word files can be exploited with [Oletools, especially olevba](https://medium.com/r3d-buck3t/extracting-macros-with-oletools-6c3a64c02549)

```terminal
$ olevba File.docm
olevba 0.60.2 on Python 3.12.7 - http://decalage.info/python/oletools
===============================================================================
FILE: File.docm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: word/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub RunPython()
    Dim Ret_Val As Integer
    Dim PythonCommand As String
    Dim CMDCommand As String
    PythonCommand: "python -c ""print('cm9vdEBsb2NhbGhvc3R7bTRjcjBzX3JfZDRuZzNyMHVzfQ==')"""
    CMDCommand: "cmd /K " & PythonCommand & " & timeout /T 0.2 & exit"
    Ret_Val: Shell(CMDCommand, vbNormalFocus)
    If Ret_Val: 0 Then
        MsgBox "Couldn't run python script!", vbOKOnly
    End If
End Sub

-------------------------------------------------------------------------------
VBA MACRO UserForm1.frm 
in file: word/vbaProject.bin - OLE stream: 'VBA/UserForm1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|vbNormalFocus       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

Base64Decoding the strings gives the flag.
```terminal
$ base64 -d <<< cm9vdEBsb2NhbGhvc3R7bTRjcjBzX3JfZDRuZzNyMHVzfQ==
root@localhost{m4cr0s_r_d4ng3r0us}
```

### Flag: `root@localhost{m4cr0s_r_d4ng3r0us}`

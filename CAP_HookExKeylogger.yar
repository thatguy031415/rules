rule CAP_HookExKeylogger
{
meta:
    author = "Brian C. Bell -- @biebsmalwareguy"
    description = "Simple YARA rule to look for keyboard hooking in an executable."
strings:
    $s1 = "SetWindowsHookEx" nocase
    $s2 = "WH_KEYBOARD_LL" nocase
    $s3 = "WH_KEYBOARD" nocase
condition:
    2 of them
}

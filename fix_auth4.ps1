$path = "D:\MyWare\DeadDropMGMT\includes\auth.php"
$content = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)

# Find function start
$startIdx = $content.IndexOf("function session_save_path_ensure(): void {")
if ($startIdx -lt 0) { "Function start not found"; exit }

# Find matching closing brace
$braceCount = 0
$endIdx = -1
for ($i = $startIdx; $i -lt $content.Length; $i++) {
    $c = $content[$i]
    if ($c -eq "{") { $braceCount++ }
    elseif ($c -eq "}") { 
        $braceCount--
        if ($braceCount -eq 0) { 
            $endIdx = $i
            break
        }
    }
}
if ($endIdx -lt 0) { "Could not find end of function"; exit }

# Build new function with literal $ signs (escape for PowerShell)
$new = "function session_save_path_ensure(): void {" + "`n" +
"    `$probe = session_effective_path();" + "`n" +
"`n" +
"    // First check: directory exists and is writable according to PHP" + "`n" +
"    if (is_dir(`$probe) && is_writable(`$probe)) {" + "`n" +
"        // Second check: actually try to write a test file to catch" + "`n" +
"        // NFS quota issues, ACL problems, noexec mounts, etc." + "`n" +
"        `$testFile = `$probe . '`/.session_write_test_`' . bin2hex(random_bytes(8));" + "`n" +
"        `$written = @file_put_contents(`$testFile, 'test', LOCK_EX);" + "`n" +
"        if (`$written !== false && `$written > 0) {" + "`n" +
"            @unlink(`$testFile);" + "`n" +
"            return; // Path is truly writable" + "`n" +
"        }" + "`n" +
"        // Test write failed -- clean up if file was created" + "`n" +
"        @unlink(`$testFile);" + "`n" +
"    }" + "`n" +
"`n" +
"    `$local = dirname(__DIR__) . '`/cache/sessions';" + "`n" +
"    if (!is_dir(`$local) && !@mkdir(`$local, 0700, true)) {" + "`n" +
"        return; // cannot improve - session_start() itself reports it" + "`n" +
"    }" + "`n" +
"    @ini_set('session.save_path', `$local);" + "`n" +
"}"

$content = $content.Substring(0, $startIdx) + $new + $content.Substring($endIdx + 1)
[IO.File]::WriteAllText($path, $content, [Text.Encoding]::UTF8)
"Success"
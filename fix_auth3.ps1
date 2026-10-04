$path = "D:\MyWare\DeadDropMGMT\includes\auth.php"
$content = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)

# Read the old function from the file itself to get exact bytes
$startIdx = $content.IndexOf("function session_save_path_ensure(): void {")
if ($startIdx -lt 0) { "Function start not found"; exit }

# Find the matching closing brace
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

$old = $content.Substring($startIdx, $endIdx - $startIdx + 1)
"Found function, length: " + $old.Length

$new = @"
function session_save_path_ensure(): void {
    $probe = session_effective_path();

    // First check: directory exists and is writable according to PHP
    if (is_dir($probe) && is_writable($probe)) {
        // Second check: actually try to write a test file to catch
        // NFS quota issues, ACL problems, noexec mounts, etc.
        $testFile = $probe . "/.session_write_test_" . bin2hex(random_bytes(8));
        $written = @file_put_contents($testFile, "test", LOCK_EX);
        if ($written !== false && $written -gt 0) {
            @unlink($testFile);
            return; // Path is truly writable
        }
        // Test write failed -- clean up if file was created
        @unlink($testFile);
    }

    $local = dirname(__DIR__) . "/cache/sessions";
    if (!is_dir($local) && !@mkdir($local, 0700, $true)) {
        return; // cannot improve - session_start() itself reports it
    }
    @ini_set("session.save_path", $local);
}
"@

$content = $content.Substring(0, $startIdx) + $new + $content.Substring($endIdx + 1)
[IO.File]::WriteAllText($path, $content, [Text.Encoding]::UTF8)
"Success"
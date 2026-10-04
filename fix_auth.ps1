$path = "D:\MyWare\DeadDropMGMT\includes\auth.php"
$content = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)

$old = @"
function session_save_path_ensure(): void {
    \$probe = session_effective_path();
    if (is_dir(\$probe) && is_writable(\$probe)) {
        return;
    }
    \$local = dirname(__DIR__) . '/cache/sessions';
    if (!is_dir(\$local) && !@mkdir(\$local, 0700, true)) {
        return; // cannot improve -- session_start() itself reports it
    }
    @ini_set('session.save_path', \$local);
}
"@

$new = @"
function session_save_path_ensure(): void {
    \$probe = session_effective_path();

    // First check: directory exists and is writable according to PHP
    if (is_dir(\$probe) && is_writable(\$probe)) {
        // Second check: actually try to write a test file to catch
        // NFS quota issues, ACL problems, noexec mounts, etc.
        \$testFile = \$probe . '/.session_write_test_' . bin2hex(random_bytes(8));
        \$written = @file_put_contents(\$testFile, 'test', LOCK_EX);
        if (\$written !== false && \$written > 0) {
            @unlink(\$testFile);
            return; // Path is truly writable
        }
        // Test write failed -- clean up if file was created
        @unlink(\$testFile);
    }

    \$local = dirname(__DIR__) . '/cache/sessions';
    if (!is_dir(\$local) && !@mkdir(\$local, 0700, true)) {
        return; // cannot improve -- session_start() itself reports it
    }
    @ini_set('session.save_path', \$local);
}
"@

if ($content.Contains($old)) {
    $content = $content.Replace($old, $new)
    [IO.File]::WriteAllText($path, $content, [Text.Encoding]::UTF8)
    Write-Host "Success"
} else {
    Write-Host "Old function not found - trying alternative"
    $old2 = @"
function session_save_path_ensure(): void {
    \$probe = session_effective_path();
    if (is_dir(\$probe) && is_writable(\$probe)) {
        return;
    }
    \$local = dirname(__DIR__) . '/cache/sessions';
    if (!is_dir(\$local) && !@mkdir(\$local, 0700, true)) {
        return; // cannot improve -- session_start() itself reports it
    }
    @ini_set('session.save_path', \$local);
}
"@
    if ($content.Contains($old2)) {
        $content = $content.Replace($old2, $new)
        [IO.File]::WriteAllText($path, $content, [Text.Encoding]::UTF8)
        Write-Host "Success with alternative"
    } else {
        Write-Host "Still not found"
    }
}
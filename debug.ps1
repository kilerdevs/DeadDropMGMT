$path = "D:\MyWare\DeadDropMGMT\includes\auth.php"
$content = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
$idx = $content.IndexOf("function session_save_path_ensure")
if ($idx -ge 0) {
    $snippet = $content.Substring($idx, 500)
    "Found at index $($idx):"
    $snippet
} else {
    "Function not found"
}
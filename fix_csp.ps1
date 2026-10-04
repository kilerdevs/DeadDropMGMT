$content = Get-Content D:\MyWare\DeadDropMGMT\includes\auth.php -Raw
$old = "style-src 'self'; ."
$new = "style-src 'self'; ." + "`n" + '            "connect-src '"'"'self'"'"'; ".'
$newContent = $content.Replace($old, $new)
Set-Content D:\MyWare\DeadDropMGMT\includes\auth.php -Value $newContent

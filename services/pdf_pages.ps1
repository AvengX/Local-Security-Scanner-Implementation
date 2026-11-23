# Renders every page of a PDF to PNG with the PDF engine built into Windows (Windows.Data.Pdf).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File pdf_pages.ps1 <pdf> <out-dir> [width]
# Prints the number of pages written. Nothing is downloaded or installed.
param([Parameter(Mandatory = $true)][string]$Pdf,
      [Parameter(Mandatory = $true)][string]$OutDir,
      [int]$Width = 1400)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Data.Pdf.PdfDocument, Windows.Data.Pdf, ContentType = WindowsRuntime]
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
$methods = [System.WindowsRuntimeSystemExtensions].GetMethods()
$asTaskOp = ($methods | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
$asTaskAction = ($methods | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]
function Wait-Op($op, [Type]$type) {
    $task = $asTaskOp.MakeGenericMethod($type).Invoke($null, @($op)); $task.Wait(); $task.Result
}
function Wait-Action($op) { $task = $asTaskAction.Invoke($null, @($op)); $task.Wait() }

$file = Wait-Op ([Windows.Storage.StorageFile]::GetFileFromPathAsync($Pdf)) ([Windows.Storage.StorageFile])
$doc = Wait-Op ([Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($file)) ([Windows.Data.Pdf.PdfDocument])
New-Item -ItemType Directory -Force $OutDir | Out-Null
for ($i = 0; $i -lt $doc.PageCount; $i++) {
    $page = $doc.GetPage($i)
    $opts = New-Object Windows.Data.Pdf.PdfPageRenderOptions
    $opts.DestinationWidth = $Width
    $stream = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream
    Wait-Action ($page.RenderToStreamAsync($stream, $opts))
    $src = [System.IO.WindowsRuntimeStreamExtensions]::AsStreamForRead($stream.GetInputStreamAt(0))
    $dst = [System.IO.File]::Create((Join-Path $OutDir ('page{0:D3}.png' -f ($i + 1))))
    $src.CopyTo($dst); $dst.Close(); $src.Close(); $page.Dispose()
}
Set-Content -Path (Join-Path $OutDir 'done.txt') -Value $doc.PageCount -Encoding ascii
Write-Output $doc.PageCount
# The Windows PDF components keep background threads alive; exit explicitly so the caller never waits.
[Environment]::Exit(0)

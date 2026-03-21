param(
    [switch]$Serve
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$buildRoot = Join-Path $repoRoot ".build"
$sourceDir = Join-Path $buildRoot "site"
$outputDir = Join-Path $buildRoot "_site"

if (Test-Path $sourceDir) {
    Remove-Item $sourceDir -Recurse -Force
}

if (Test-Path $outputDir) {
    Remove-Item $outputDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $sourceDir | Out-Null
Copy-Item (Join-Path $repoRoot "site\*") $sourceDir -Recurse -Force

$articlesDir = Join-Path $sourceDir "_articles"
New-Item -ItemType Directory -Force -Path $articlesDir | Out-Null

Get-ChildItem (Join-Path $repoRoot "content\posts\*.md") | ForEach-Object {
    $targetName = $_.Name -replace '^post-\d+-', ''
    Copy-Item $_.FullName (Join-Path $articlesDir $targetName) -Force
}

Copy-Item (Join-Path $repoRoot "content\pages\about-me.md") (Join-Path $sourceDir "about.md") -Force

$imagesSource = Join-Path $repoRoot "content\images"
if (Test-Path $imagesSource) {
    Copy-Item $imagesSource (Join-Path $sourceDir "images") -Recurse -Force
}

Push-Location (Join-Path $repoRoot "site")
try {
    if ($Serve) {
        bundle exec jekyll serve --source $sourceDir --destination $outputDir
    } else {
        bundle exec jekyll build --source $sourceDir --destination $outputDir
    }
} finally {
    Pop-Location
}

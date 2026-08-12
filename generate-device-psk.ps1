param(
    [ValidateRange(16, 64)]
    [int]$Bytes = 16
)

# Generate a cryptographically random PSK and print it once. The default is
# 16 random bytes represented as 32 hexadecimal characters (128 bits).
$buffer = New-Object byte[] $Bytes
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

try {
    $rng.GetBytes($buffer)
} finally {
    $rng.Dispose()
}

($buffer | ForEach-Object { $_.ToString('x2') }) -join ''

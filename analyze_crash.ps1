param([Parameter(Mandatory)][string]$Path)

# Richer minidump analyzer: pulls the crashing thread's CONTEXT (x64
# registers), walks the stack memory range from MemoryListStream, and
# tries to attribute return addresses on the stack to loaded modules.
# Useful when cdb/windbg aren't installed locally.

$bytes = [System.IO.File]::ReadAllBytes($Path)
$ms = [System.IO.MemoryStream]::new($bytes)
$br = [System.IO.BinaryReader]::new($ms)

[void]$br.ReadBytes(4)
[void]$br.ReadUInt32()
$nStreams = $br.ReadUInt32()
$dirRva = $br.ReadUInt32()
[void]$br.ReadBytes(16)

$ms.Position = $dirRva
$entries = @()
for ($i = 0; $i -lt $nStreams; $i++) {
	$entries += [pscustomobject]@{ Type=$br.ReadUInt32(); DataSize=$br.ReadUInt32(); Rva=$br.ReadUInt32() }
}

function Get-Stream($type) { $entries | Where-Object { $_.Type -eq $type } | Select-Object -First 1 }

# Exception stream -- find the crashing thread id + RIP
$exc = Get-Stream 6
$ms.Position = $exc.Rva
$crashThreadId = $br.ReadUInt32()
[void]$br.ReadUInt32() # alignment
$excCode  = $br.ReadUInt32()
[void]$br.ReadUInt32() # flags
[void]$br.ReadUInt64() # nested
$excAddr  = $br.ReadUInt64()

"Crash thread: $crashThreadId"
"Exception:    0x{0:x8}  at 0x{1:x16}" -f $excCode, $excAddr
""

# Module list
$mods = Get-Stream 4
$ms.Position = $mods.Rva
$nModules = $br.ReadUInt32()
$moduleList = @()
for ($i = 0; $i -lt $nModules; $i++) {
	$base = $br.ReadUInt64(); $size = $br.ReadUInt32()
	[void]$br.ReadUInt32(); [void]$br.ReadUInt32()
	$nameRva = $br.ReadUInt32(); [void]$br.ReadBytes(84)
	$moduleList += [pscustomobject]@{ Base=$base; Size=$size; End=$base+$size; NameRva=$nameRva; Name='' }
}
foreach ($m in $moduleList) {
	$ms.Position = $m.NameRva
	$len = $br.ReadUInt32()
	$m.Name = [System.Text.Encoding]::Unicode.GetString($br.ReadBytes($len))
}
function Resolve-Address($addr) {
	$m = $moduleList | Where-Object { $addr -ge $_.Base -and $addr -lt $_.End } | Select-Object -First 1
	if ($m) {
		$leaf = Split-Path $m.Name -Leaf
		return "{0}+0x{1:x}" -f $leaf, ($addr - $m.Base)
	}
	return "<unknown>"
}

# Thread list -- find context for the crashing thread
$threads = Get-Stream 3
$ms.Position = $threads.Rva
$nThreads = $br.ReadUInt32()
$crashContext = $null
$crashStackStart = 0
$crashStackSize = 0
$crashStackRva = 0
for ($i = 0; $i -lt $nThreads; $i++) {
	$tid = $br.ReadUInt32()
	[void]$br.ReadUInt32(); [void]$br.ReadUInt32(); [void]$br.ReadUInt32()
	[void]$br.ReadUInt64()
	$stackStart = $br.ReadUInt64()
	$stackSize = $br.ReadUInt32()
	$stackRva = $br.ReadUInt32()
	[void]$br.ReadUInt32() # ctxSize
	$ctxRva = $br.ReadUInt32()
	if ($tid -eq $crashThreadId) {
		$crashContext = $ctxRva
		$crashStackStart = $stackStart
		$crashStackSize = $stackSize
		$crashStackRva = $stackRva
	}
}

if ($crashContext) {
	$ms.Position = $crashContext + 0x78
	$rax = $br.ReadUInt64(); $rcx = $br.ReadUInt64(); $rdx = $br.ReadUInt64(); $rbx = $br.ReadUInt64()
	$rsp = $br.ReadUInt64(); $rbp = $br.ReadUInt64(); $rsi = $br.ReadUInt64(); $rdi = $br.ReadUInt64()
	$r8 = $br.ReadUInt64(); $r9 = $br.ReadUInt64(); $r10 = $br.ReadUInt64(); $r11 = $br.ReadUInt64()
	$r12 = $br.ReadUInt64(); $r13 = $br.ReadUInt64(); $r14 = $br.ReadUInt64(); $r15 = $br.ReadUInt64()
	$rip = $br.ReadUInt64()

	"=== Crash thread registers ==="
	"  RIP = 0x{0:x16}  ({1})" -f $rip, (Resolve-Address $rip)
	"  RSP = 0x{0:x16}" -f $rsp
	"  RBP = 0x{0:x16}" -f $rbp
	"  RAX = 0x{0:x16}" -f $rax
	"  RCX = 0x{0:x16}" -f $rcx
	"  RDX = 0x{0:x16}" -f $rdx
	"  R8  = 0x{0:x16}" -f $r8
	"  R9  = 0x{0:x16}" -f $r9
	""

	"=== Stack scan (return-addr-like values within loaded modules) ==="
	"  stack range: 0x{0:x} .. 0x{1:x}  (size 0x{2:x})" -f $crashStackStart, ($crashStackStart + $crashStackSize), $crashStackSize
	if ($crashStackRva -gt 0 -and $crashStackSize -gt 0) {
		$ms.Position = $crashStackRva
		$stackBytes = $br.ReadBytes($crashStackSize)
		$count = 0
		for ($off = 0; $off -le ($crashStackSize - 8); $off += 8) {
			$val = [System.BitConverter]::ToUInt64($stackBytes, $off)
			$m = $moduleList | Where-Object { $val -ge $_.Base -and $val -lt $_.End } | Select-Object -First 1
			if ($m) {
				$leaf = Split-Path $m.Name -Leaf
				$addr = $crashStackStart + $off
				"  [rsp+0x{0:x4}]  0x{1:x16}  ->  {2}+0x{3:x}" -f ($addr - $rsp), $val, $leaf, ($val - $m.Base)
				$count++
				if ($count -gt 100) { "  ... (truncated, showing first 100)"; break }
			}
		}
	}
}

$br.Close(); $ms.Close()

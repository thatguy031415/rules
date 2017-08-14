import "magic"
rule hancitor {
	meta:
		description = "Rule to catch new versions of Hancitor dropper document"
		author = "Brian C. Bell - @Biebermalware"

	strings:
		$api1 = "ntdll.dll" nocase
		$api2 = "NtWriteVirtualMemory" nocase
		$api3 = "NtAllocateVirtualMemory" nocase

	condition: magic.type() contains "Document" and all of ($api*)
}

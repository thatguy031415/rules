rule rtfWithPE
{
	meta:
		description = "Rule to catch RTF with embedded PE file"
		author = "Brian C. Bell - @Biebermalware"
	strings:
    	$rtfHead = {7B 5C 72 74}
    	$peString = {34 64 35 61 (35|36|37|38|39) 30 30 30}
    condition:
    	$rtfHead at 0 and $peString
}

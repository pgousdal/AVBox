/* AVBox controlled harmless M1 qualification rules, version 1.0.0. */
rule AVBox_Harmless_Positive
{
    meta:
        source = "AVBox project"
        purpose = "functional qualification only"
        version = "1.0.0"
    strings:
        $marker = "AVBOX_M1_HARMLESS_POSITIVE_7F45D8"
    condition:
        $marker
}

rule AVBox_Harmless_Second
{
    meta:
        source = "AVBox project"
        purpose = "multiple-match qualification"
        version = "1.0.0"
    strings:
        $marker = "AVBOX_M1_HARMLESS_MULTIPLE_B30A26"
    condition:
        $marker
}

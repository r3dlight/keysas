rule contains_dirtycow
{
  meta:
    author ="Stephane N"
    date = "29/12/2020"
    description = "Basic test rule matching dirtyc0w"
  strings:
    $var1 = "dirtyc0w" nocase
  condition:
    $var1
}


$input = ".\input.txt"

$out = Get-Content -Path $input
$enc = [System.IO.File]::ReadAllBytes("$input")
$encoding = [system.Text.Encoding]::UTF8
$total = 264
$t = ($total + 1) * 5 #spaces
$numLength = ($total * 30 ) + $t #264*30 + (264+1)*5 == 9245
if ($out.Length -gt 5) #-or $enc.count -ne $numLength) #encrypted data length == 9245
													 #out.length is the nunber of lines
													 #-or $enc.count -ne $numLength
{
	echo $out.length
  Write-Output "Wrong format 5"
  Exit
}

else
{
  for($i=0; $i -lt $enc.count ; $i++)
  {
	  #Write-Output $enc[$i]
    if (($enc[$i] -ne 49) -and ($enc[$i] -ne 48) -and ($enc[$i] -ne 10) -and ($enc[$i] -ne 13) -and ($enc[$i] -ne 32)) #Contents MUST be 1 of these types
	#1 0 some unprintable chars
    {
      Write-Output "Wrong format 1/0/"
      Exit
    }
  }
}
# [][][][][][] [][][][][][] .....
# 101010 101010 .....
# [][][][][][] .....
# [][][][][][] .....
# [][][][][][] .....
# - 5 lines
# - Split by spaces in each line, with each element having length 6
# - 264 columns
# Creates a hash table with EACH COLUMN becoming a line in the hash table
$blocks = @{}

for ($i=0; $i -lt $out.Length ; $i++) #Iterate through contents by each line
{
  $r = $out[$i].Split(" ") #Split each line by spaces
  #$r = 101010 101010 101010
  #$r[$j] = 101010
  if ($i -gt 0)
  {
    for ($j=0; $j -lt $r.Length ; $j++)
    {
		
    if ($r[$j].Length -ne 6) #In each element of $r, the strlen should be 6
    {
      Write-Output "Wrong Format 6" $r[$j].Length
	  Write-Output "died"
      Exit
    }
	#Write-Output $r[$j]
	#Write-Output "mello"
      $blocks[$j] += $r[$j] #Append each stuff to their respective columns
    }
  }
  else
  {
    for ($j=0; $j -lt $r.Length ; $j++)
    {
		#Write-Output $r
		#Write-Output "hello"
		#Write-Output $r[$j]
    if ($r[$j].Length -ne 6)
    {
      Write-Output "Wrong Format 6" $r[$j].Length
	  Write-Output "diedddd"
      Exit
    }
	#Creates columns using the first line in the file
      $blocks[$j] = @()
      $blocks[$j] += $r[$j]
	  #Write-Output "hello"
	  #Write-Output $blocks
    }
  }

}
#Write-Output $blocks
function Exit  {
  exit
}


function Random-Gen {
  $list1 = @()
  for ($i=1; $i -lt ($blocks.count + 1); $i++)
  {
    $y = ((($i * 327) % 681 ) + 344) % 313
    $list1 += $y
  }
  return $list1
}


function Scramble {
    param (
        $block,
        $seed
    )

    $raw = [system.String]::Join("", $block) #Joins the block
	#Write-Debug $raw
    $bm = "10 " * $raw.Length #raw.length == 30
	#Takes the length of the block and creates "10" * length
	#Write-Debug $bm
    $bm = $bm.Split(" ")
	#Write-Debug [system.String]::Join("", $bm)
	
	
    for ($i=0; $i -lt $raw.Length ; $i++) #Iterate through raw
    {

      $y = ($i * $seed) % $raw.Length
	  #Write-Debug $y
      $n = $bm[$y]
	  #Write-Debug "n"
	  #Write-Debug $bm[$y]
      while ($n -ne "10")
      {
        #Prevent hash table collisions - linear looping search
        $y = ($y + 1) % $raw.Length
        $n = $bm[$y]
		#If the current $bm is not 10 (means modified already), set the value to 10  
      }
      if ($raw[$i] -eq "1" )
      {
        $n = "11"
      }
      else
      {
      $n = "00"
      }
      $bm[$y] = $n #modifies $bm in each iteration
    }
    $raw2 = [system.String]::Join("", $bm) 
	#Write-Debug $raw2
    $b = [convert]::ToInt64($raw2,2) #Returns $bm
	#Converts the binary string to integer
    return $b
}


$result = 0
$seeds = @()
#Creates seeds
#127, 254, 381, 8, 135...
for ($i=1; $i -lt ($blocks.count +1); $i++)
{
  $seeds += ($i * 127) % 500
}

$randoms = Random-Gen
$output_file = @()
for ($i=0; $i -lt $blocks.count ; $i++) #Iterate through the hash table
#264 columns
{
  $fun = Scramble -block $blocks[$i] -seed $seeds[$i] #Pass a "block"(an element in the hash table OR A COLUMN) and "seed"
  #Write-Debug $fun
  if($i -eq 263) 
  {
  Write-Output $seeds[$i]
  Write-Output $randoms[$i]
  Write-Output $fun
  }
  Write-Debug $seeds[$i]
  Write-Debug $randoms[$i]
  Write-Debug $fun
  $result = $fun -bxor $result -bxor $randoms[$i] #!!!!
  #Each line in outputGiven.txt is this shit
  #Each line xors the previous line
  $output_file += $result
}
  Add-Content -Path output.txt -Value $output_file

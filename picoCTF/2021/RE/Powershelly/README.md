# Powershelly [180 Points] - 101 Solves

```
It's not a bad idea to learn to read Powershell. We give you the output, but do you think you can find the input? rev_PS.ps1 output.txt
```

We are given a powershell script `rev_PS.ps` and `output.txt`

This challenge is just simply tedious. Hence I will not be going through the entire script, but you can find my fully annotated script in this folder.

A short summary of what this does:

1. ```powershell
   $input = ".\input.txt"
   $out = Get-Content -Path $input
   $enc = [System.IO.File]::ReadAllBytes("$input")
   $encoding = [system.Text.Encoding]::UTF8
   $total = 264
   $t = ($total + 1) * 5 #spaces
   $numLength = ($total * 30 ) + $t #264*30 + (264+1)*5 == 9245
   if ($out.Length -gt 5 -or $enc.count -ne $numLength) #encrypted data length == 9245
   													 #out.length is the nunber of lines
   													 #-or $enc.count -ne $numLength
   {
   	echo $out.length
     Write-Output "Wrong format 5"
     Exit
   }
   ```

   - Obtains the bytes from a file named `input.txt`. Checks that there are exactly `9245` bytes and `<= 5` lines

2. ```powershell
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
   ```

   - Ensures that the bytes in `input.txt` can only be these 5 types (which are `0`, `1`, `\n`, `carriage returns` and `spaces`)

3. ```powershell
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
   ```

   - Creates a **hash table** where **EACH COLUMN** is an **entry in the hash table** (rather than each row)

4. ```powershell
   $result = 0
   $seeds = @()
   #Creates seeds
   #127, 254, 381, 8, 135...
   for ($i=1; $i -lt ($blocks.count +1); $i++)
   {
     $seeds += ($i * 127) % 500
   }
   ```

   - Creates the seeds shown in the comment

5. ```powershell
   $randoms = Random-Gen
   
   function Random-Gen {
     $list1 = @()
     for ($i=1; $i -lt ($blocks.count + 1); $i++)
     {
       $y = ((($i * 327) % 681 ) + 344) % 313
       $list1 += $y
     }
     return $list1
   }
   ```

   - Generates more numbers based on the length of `$blocks`

6. ```powershell
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
   ```

   - We can deduce from this that there are `264 columns`
   - `$result`, which is **each line** in `output.txt`, is the result of `$fun ^ $result ^ $randoms[i]`, which means that **each line depends on the previous 1, and 1 incorrect line results in everything after it being wrong**

After much trial and error, I came up with the python script you can find in this folder.

After getting the right `input.txt`, we notice that in each line, there are only 2 combinations of numbers, and hence we can deduce it is binary. By replacing the combinations with `0`/`1`s, we get the flag:

```
picoCTF{2018highw@y_2_pow3r$hel!}
```


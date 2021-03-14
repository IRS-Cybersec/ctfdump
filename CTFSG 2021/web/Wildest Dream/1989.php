<!DOCTYPE HTML>
<!--
	Helios by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html>
	<head>
		<title>BTBLP</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="no-sidebar is-preload">
		<div id="page-wrapper">

			<!-- Header -->
				<div id="header">

					<!-- Inner -->
						<div class="inner">
							<header>
								<h1><a href="index.html" id="logo">Wildest Dreams</a></h1>
							</header>
						</div>

					<!-- Nav -->
					<nav id="nav">
						<ul>
							<li><a href="index.php">Home</a></li>

							<li><a href="1989.php">1989</a></li>
						</ul>
					</nav>

				</div>

			<!-- Main -->
				<div class="wrapper style1">

					<div class="container">
						<article id="main" class="special">
							<header>
								<h2><a href="#">I could be in your wildest dream.</a></h2>
								<p>
									I'm like the water when your ship rolled in that night<br>
									Rough on the surface but you cut through like a knife
								</p>
							</header>
							<a href="#" class="image featured"><img src="images/tsbg.jpg" alt="" /></a>
							
							<?php
								if(!empty($_GET['i1']) && !empty($_GET['i2'])){
									$i1 = $_GET['i1'];
									$i2 = $_GET['i2'];
									if($i1 === $i2){
										die("i1 and i2 can't be the same!");
									}
									$len1 = strlen($i1);
									$len2 = strlen($i2);
									if($len1 < 20){
										die("i1 is too shorttttttt pee pee pee pee pee");
									}
									if($len2 < 20){
										die("i2 is too shorttttttt pee pee pee pee pee");
									}
									if(sha1(hex2bin($i1)) === sha1(hex2bin($i2)));
										if(md5(hex2bin($i1)) !== md5(hex2bin($i2)))
											echo "All I want to be is in your wildest dreams";
											if(md5(hex2bin($i1)) == md5(hex2bin($i2)))echo $flag;
									echo "<br>I think he did it, but i just cant prove it.";
								} else {
									echo "<br> You need to provide two strings, i1 and i2. /1989.php?i1=a&i2=b";
								}
								
								
							?>
							
						</article>
						
					</div>

				</div>

			<!-- Footer -->
				<div id="footer">
					<div class="container">
						<div class="row">

							<!-- Photos -->

						</div>
						<hr />
						<div class="row">
							<div class="col-12">

								<!-- Contact -->

								<!-- Copyright -->

							</div>

						</div>
					</div>
				</div>

		</div>

		<!-- Scripts -->
			<script src="assets/js/jquery.min.js"></script>
			<script src="assets/js/jquery.dropotron.min.js"></script>
			<script src="assets/js/jquery.scrolly.min.js"></script>
			<script src="assets/js/jquery.scrollex.min.js"></script>
			<script src="assets/js/browser.min.js"></script>
			<script src="assets/js/breakpoints.min.js"></script>
			<script src="assets/js/util.js"></script>
			<script src="assets/js/main.js"></script>

	</body>
</html>
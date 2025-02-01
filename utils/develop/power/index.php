<?php

?>


<html>
<script>
'use strict';
(

function () {
	function init() {

		
		var year2end = new Date();
		var year2start = new Date();
		year2start.setHours(year2start.getHours() - 2);


		var year1end = new Date();
		year1end.setFullYear(year2end.getFullYear() - 1);
				
		var year1start = new Date();
		year1start.setFullYear(year2start.getFullYear() - 1);
		year1start.setHours(year1start.getHours() - 2);
	
	
		const y2Smilliseconds = year2start.getTime();
		const y2Emilliseconds = year2end.getTime();	
		const y1Smilliseconds = year1end.getTime();	
		const y1Emilliseconds = year1start.getTime();	
	
	
		document.getElementById('year1start')
			.innerHTML = y1Smilliseconds;
			
		document.getElementById('year1end')
			.innerHTML = y1Emilliseconds;
			
		document.getElementById('year2start')
			.innerHTML = y2Smilliseconds;
			
		document.getElementById('year2end')
			.innerHTML = y2Emilliseconds;
			
		var year1iframeSrc="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=" + y1Smilliseconds + "&to=" + y1Emilliseconds
		console.log(year1iframeSrc)
		document.getElementById("year1").src = year1iframeSrc;
		
		var year2iframeSrc="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=" + y2Smilliseconds + "&to=" + y2Emilliseconds
		console.log(year2iframeSrc)			
		document.getElementById("year2").src = year2iframeSrc;
		
	}
	document.addEventListener("DOMContentLoaded", function () {
		init();
	});
}()



);

</script>
<body>

<main>
	<h2>Datumsausgaben formatieren</h2>
	<p> <b>2024 start:</b>
		<time id="year1start"></time>
	</p>
	<p> <b>2024 end:</b>
		<time id="year1end"></time>
	</p>
	<p> <b>2025 start:</b>
		<time id="year2start"></time>
	</p>
	<p> <b>2025 end:</b>
		<time id="year2end"></time>
	</p>
</main>

<time aria-current="date" id="zeit"></time>

<iframe style="height:600px;width:1400px;" id=year1 src="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=1704063600000&to=1704841200000"></iframe>
2024 JAN 01-02  / 
2025 JAN 01-02
<br/>
<iframe style="height:600px;width:1400px;" id=year2 src="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=1735686000000&to=1736463600000"></iframe>

</body>

</html>
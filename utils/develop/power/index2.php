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
		year1end.setHours(year1end.getHours() - 2);
				
		var year1start = new Date();
		year1start.setHours(year1start.getHours() - 4);
	
	
		const y2Smilliseconds = year2start.getTime();
		const y2Emilliseconds = year2end.getTime();	
		const y1Smilliseconds = year1start.getTime();	
		const y1Emilliseconds = year1end.getTime();	
	
		const y2Smilliseconds_date = year2start;
		const y2Emilliseconds_date = year2end;
		const y1Smilliseconds_date = year1start;
		const y1Emilliseconds_date = year1end;
		
	
		document.getElementById('year1start_date')
			.innerHTML = y1Smilliseconds_date;
			
		document.getElementById('year1end_date')
			.innerHTML = y1Emilliseconds_date;
			
		document.getElementById('year2start_date')
			.innerHTML = y2Smilliseconds_date;
			
		document.getElementById('year2end_date')
			.innerHTML = y2Emilliseconds_date;
			
		var year1iframeSrc="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=" + y1Smilliseconds + "&to=" + y1Emilliseconds
		document.getElementById("year1").src = year1iframeSrc;
		
		var year2iframeSrc="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=" + y2Smilliseconds + "&to=" + y2Emilliseconds
		document.getElementById("year2").src = year2iframeSrc;
		
	}
	document.addEventListener("DOMContentLoaded", function () {
		init();
	});
	
}()



);

	function test(){
	
		var timeframe
		const timeframe_field = document.getElementById("timeframe");
		timeframe = timeframe_field.value;
	
		var calcYear1End
		const inputYear1 = document.getElementById("time_year1");
		calcYear1End = inputYear1.value;
		const date1End = new Date(calcYear1End)
		const date1Start = new Date(calcYear1End)
		date1Start.setHours(date1Start.getHours() - timeframe);
				
		var calcYear2End
		const inputYear2 = document.getElementById("time_year2");
		calcYear2End = inputYear2.value;
		const date2End = new Date(calcYear2End)
		const date2Start = new Date(calcYear2End)
		date2Start.setHours(date2Start.getHours() - timeframe);	
			
		
		const calc_y2Smilliseconds = date2Start.getTime();
		const calc_y2Emilliseconds = date2End.getTime();	
		const calc_y1Smilliseconds = date1Start.getTime();	
		const calc_y1Emilliseconds = date1End.getTime();	


		const calc_y2Smilliseconds_date = date2Start;
		const calc_y2Emilliseconds_date = date2End;	
		const calc_y1Smilliseconds_date = date1Start;	
		const calc_y1Emilliseconds_date = date1End;	
			
	
	
	
	
		document.getElementById('calc_year1start_date')
			.innerHTML = calc_y1Smilliseconds_date;
			
		document.getElementById('calc_year1end_date')
			.innerHTML = calc_y1Emilliseconds_date;
			
		document.getElementById('calc_year2start_date')
			.innerHTML = calc_y2Smilliseconds_date;
			
		document.getElementById('calc_year2end_date')
			.innerHTML = calc_y2Emilliseconds_date;
			
				
		
		var year1iframeSrc="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=" + calc_y1Smilliseconds + "&to=" + calc_y1Emilliseconds
		document.getElementById("year1").src = year1iframeSrc;
		
		var year2iframeSrc="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&from=" + calc_y2Smilliseconds + "&to=" + calc_y2Emilliseconds
		document.getElementById("year2").src = year2iframeSrc;
	}
</script>
<body>

<label for="meeting-time">graph1:</label>

<input
  type="datetime-local"
  id="time_year1"
  name="meeting-time"
  value="2025-01-26T11:53"
  min="2024-01-01T00:00"
  max="2026-01-01T00:00" />
  
<label for="meeting-time">graph2:</label>

<input
  type="datetime-local"
  id="time_year2"
  name="meeting-time"
  value="2025-01-26T10:00"
  min="2024-01-01T00:00"
  max="2026-01-01T00:00" />


<input
  type="text" 
  id="timeframe"
  value="24" /> hours
  
<button onclick = "test()" > Click Me </button>

<main>
	<h2>Datumsausgaben berechnen</h2>
	<p> <b>graph1 start:</b>	
		<time id="calc_year1start_date"></time>
		<b>end:</b>          
		<time id="calc_year1end_date"></time>
	</p>
	<p> <b>graph2 start:</b>
		<time id="calc_year2start_date"></time>
		<b>grap2 end:</b>
		<time id="calc_year2end_date"></time>
	</p>
</main>

<time aria-current="date" id="zeit"></time>

<iframe style="height:600px;width:1400px;" id=year1 src="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&kiosk&from=1737241140000&to=1737327540000"></iframe>
<iframe style="height:600px;width:1400px;" id=year2 src="https://dashboard.gpdcoy-frqszl.vivavis.cloud/d/vWnxqK3Vz/startseite-sw-neuburg?orgId=1&kiosk&from=1735686000000&to=1736463600000"></iframe>

</body>

</html>
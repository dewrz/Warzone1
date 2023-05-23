# CTF: Warzone1

Today I'll be completeing a CTF on THM as continued practice and skill building.

The scenario: So I work for an MSSP and I received multiple alerts that I have to triage to confirm if it's a true positive or negative. I will have to investigagte PCAPs for the IOC's. They gave us Wireshark, Brim, and Network Miner for our investigation.

We will first seek out the alert signature of a possible C2 by utilizing this search query in Brim:

<b>event_type=="alert"|count() by alert.severt,alert.category|sort count</b>
<br>
<br>
<img src="https://i.imgur.com/KxRHjyQ.jpg">
<br>
<br>
I then searched the traffic view to inspect the alert's content to receive the alert signature.
<br>
<br>
<img src="https://i.imgur.com/M90AzHH.jpg">
<br>
<br>
Next, they asked me for the defanged source IP address for the investigation. The use of defanged IP addresses is to decrease the risk of accidental use. The defanged IP is: <b>172[.]16[.]1[.]102</b>
<br>
<br>
<img src="https://i.imgur.com/z1Lsl01.jpg">
<br>
<br>
In the follow-up question, they are looking for the defanged destination IP address, which is: <b>169[.]239[.]128[.]11</b>
<br>
<br>
<img src="https://i.imgur.com/eXv1wnn.jpg">
<br>
<br>
I will now inspect the destination IP address in VirusTotal to check passive DNS replication. This can give us an idea of where the domain may have pointed to in the past, what subdomains may exist, do the domains point to a given IP network or what domain names may be hosted by a given name server. Upon inspection, it looks like the domain with the most detections is <b>fidufagios[.]com</b>.
<br>
<br>
<img src="https://i.imgur.com/NY6vEeZ.jpg">
<br>
<br>
While in VirusTotal I also look up the threat group and malware family attributed to this address which is <b>TA505</b> and <b>Mirrorblast</b>. This information was found under the community and relations tabs.
<br>
<br>
The investigation is also asking for the majority file type of communicating files associated with this IP. This is also found under the relations tab on VirusTotal. The majority communicating file is a Windows installer. (This is not true as per VirusTotal, which is a win32 exe. This is a process where dll's are stored)
<br>
<br>
<img src="https://i.imgur.com/h8LOdIn.jpg">
<br>
<br>
Next up we'll inspect the user agent of the suspect IP address. We will use this search string to weed out the answer: <b>_path=="http" | cut id.orig_h,id.resp_h,id.resp_p,user_agent | uniq -c</b>
<br>
<br>
<img src="https://i.imgur.com/CZKhU35.jpg">
<br>
<br>
There are two other IP addresses here that were found when running the search query:
<b>_path=="http" |cut id.orig_h ,id.resp_h ,host | uniq -c</b>
<br>
After checking IP addresses against VirusTotal they appear to also have connections to the threat group TA505. (Another thing the creators of this CTF took into consideration is that 3 of the IP addresses besides the original are all connected to TA505)
<br>
<br>
<img src="https://i.imgur.com/Pmp58n7.jpg">
<br>
<br>
There were two files downloaded by the two supporting IP addresses. I ran the search string: <b>_path=="http" | cut id.orig_h,id.resp_h, host, method, uri | uniq -c</b>  which enabled me to find one of the file names. but I had to do a generic search on the IP address and search the packet details to find the other file.
<br>
<br>
<img src="https://i.imgur.com/zBqufTP.jpg">
<br>
<br>
<img src="https://i.imgur.com/QaIAw6p.jpg">
<br>
<br>
There were also two files that were downloaded from 185.10.68.235 with the filter.msi file. We will open Wireshark to dig a little deeper. When in Wireshark I searched the traffic for the IP and followed the TCP stream to get a more granular perspective. 
<br>
<br>
<img src="https://i.imgur.com/1WhzAI9.jpg">
<br>
<br>
Finally, I will inspect the other file downloaded from 192.36.27.92 which also downloaded two other files. I will take the same approach by opening the pcap in Wireshark and following the TCP stream for a closer look.
<br>
<br>
<img src="https://i.imgur.com/fkCEpmH.jpg">
<br>
<br>
That concludes this CTF. It was interesting and good practice, but I think it's time I move on to more difficult challenges.





















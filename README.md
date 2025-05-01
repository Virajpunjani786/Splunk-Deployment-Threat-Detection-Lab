# Splunk - Boss of the SOC v1


My progress through the version 1 challenge.

I just want to give credit to those at Splunk involved in making the Boss of the SOC - version 1. I do not want to spoil anything for those who have not completed the lab, but it made me enjoy this one because of the storyline. Here in this reposiotry I have gone through both scenarios of the boss of the soc version 1. 

I originally completed the lab on https://bots.splunk.com and then set up a virtual machine using VirtualBox. I used Ubuntu 20.04 LTS and installed Splunk's Enterprise deb file. I then downloaded the data set from https://github.com/splunk/botsv1. GitHub also has a list of apps you should install. I extracted the 9.3GB data set and added it to Splunk. Now we can play with Splunk's SPL queries and work through the case.

<p align="center">
    <img src="/Scenarios/Screenshots/bots_logo.png">
</p>

<br>
Now here is the breakdown of both scenario's:

[Scenario 1]

[Scenario 2]

# Scenario 1 - Web Site Defacement


Below is the scenario 1 from Splunk's site:

> Today is Alice's first day at the Wayne Enterprise Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprise's IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.


Splunk quick reference guide: https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf

## Questions:
1. What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

2. What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

3. What content management system is imreallynotbatman.com likely using?

4. What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

5. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

6. What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

7. What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

8. What is the name of the executable uploaded by Po1s0n1vy?

9. What is the MD5 hash of the executable uploaded?

10. GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

11. What special hex code is associated with the customized malware discussed in question 111?

12. What was the first brute force password used?

13. One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

14. What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

15. What was the average password length used in the password brute forcing attempt?

16. How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

17. How many unique passwords were attempted in the brute force attempt?


## Starting the Investigate

I was searching online for a good methodology on how to start looking into an alert and saw several posts on a simple query that lets you familiarize yourself with the dataset.
```
| metadata type=sourcetypes index="botsv1" 
```
![metadata](/Scenarios/Screenshots/metadata.png)

Now we can get an idea of what sourcetypes we are working with, along with how many logs are in each.


### 1
I started by using the index="botvs1" and searching for imreallynotbatman.com to get an idea of traffic and any interesting fields data that stands out. 
```
index="botsv1" imreallynotbatman.com
```
Right off the bat (see what I did there =P), I see src_ip has three IP's with 40.80.148.42 showing 47,649 hits.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_src_ip.png">
</p>



### 2
To answer 2, I continued to use the last query and could see from the output that src_header has some interesting data. Clicking on src_header, I am able to figure out that Po1s0n1vy used Acunetix.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_acunetix.png">
</p>



### 3
3 took me a second. Personally in my career, I have helped a web team and only have seen NGINX and WordPress. After a quick Google of common CMS tools, I saw Joomla. As you would have it, Joomla shows up on the src_header option from the last question. 



### 4
Looking at the Suricata logs with the source IP as the web server, I was poking through the interesting fields and came across http.http_content_type. This showed one image. 
<p align="center">
    <img src="/Scenarios/Screenshots/s1_jpeg.png">
</p>
I then expanded the raw text option and found the jpeg file name. This data also helps point us to the next question. It pays to sometimes read a ahead so you have an idea of the next few questions =P
<p align="center">
    <img src="/Scenarios/Screenshots/s1_batmanjpeg.png">
</p>



### 5
From number 4's image of the jpeg, we can see the image came from prankglassinebracket.jumpingcrab.com. NOt sure if it's an easter egg or not but the port is 1337 or LEET. 



### 6
Number 4 also shows the IP as the dest_IP: 23.22.63.114



### 7
Knowing that you have to POST form data to a web server, we can craft a query to see what IP's have been hitting the server.
```
index="botsv1" sourcetype="stream:http" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
| stats count by src_ip
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_bruteforce_ip.png">
</p>



### 8
For this one, I just added .exe to the search field and only had two hits. I did not know what shtml was so after looking it up, I could rule it out; giving me 3791.exe
<p align="center">
    <img src="/Scenarios/Screenshots/s1_exe.png">
</p>


### 9
I was having no luck just looking in fields and raw data. I switched between sysmon logs and suricata. Just searching the index for the file name and piping it to stats value(md5) gave me what I needed.Also noticed that when looking up the 23.22.63.114 IP on threatminer.org that is had three md5 hashes. The middle one being the md5 hash that sysmon logs showed.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_md5hash.png">
</p>



### 10
This on uses OSINT to find. When we scanned the attacker's IP in VirusTotal, we can see the MirandaTateScreensaver.scr.exe file under "Communicating Files (4)". VirusTotal provides us with the SHA256 hash.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_sha256.png">
</p>



### 11
While still on VirusTotal, go over to the community tab. Knowing that the BotSv1 was in 2016, find the oldest comment that has the hex code. Head over to CyberChef and bake.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_hex.png">
</p>
<p align="center">
    <img src="/Scenarios/Screenshots/s1_cyberchef.png">
</p>



### 12
Take the query from 7 and remove the stats option and add:
```
| table _time form_data
| reverse
```
You can disregard reverse if you want to just click on _time's sort option.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_firstpw.png">
</p>



### 13
Searching around for Coldplay songs that had six letters and then looking at the list of passwords used. There are 214 passwords that are six letters long. We can use a search and check against a list from whatever source you found the list of songs. I did not use "Fix You" because of the space.
```
| eval pwlen=len(userpassword)
| search pwlen=6
| where userpassword  in ("clocks", "oceans", "sparks", "shiver", "yellow")
| table userpassword
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_coldplay.png">
</p>
<p align="center">
    <img src="/Scenarios/Screenshots/s1_yellow.png">
</p>


### 14
This one wasn't hard but I need more experience using rex expressions. We can continue working off the query from 7 and 12.
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats count by userpassword
```
We can see from the count that "batman" is the only password used twice hinting that it is the correct password.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_correctpw.png">
</p>



### 15
This one was a bit tricky for me. I had to do a lot of searching for way to average as well as figure out the syntax.
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| eval pwlen=len(userpassword)
| stats avg(pwlen) AS avglen
| eval avglen=round(avglen,0)
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_pwlength.png">
</p>



### 16
Working off of the query from 17, lets change out the last portion to utilize search and transaction. This will only look at the times batman is used and check the time it took between uses. Round to two decimal places.
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=batman
| transaction userpassword
| table duration
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_pwtime.png">
</p>



### 17
Still using the rex expression, we can use stats to count by unique (or distinc count) passwords.
You can see that there are 413 total but remember one of the passwords was used twice once it was figured out. 
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats dc by userpassword
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_uniquepw.png">
</p>




# Scenario 2 - Rasomware



Below is the scenario 2 from Splunk's site:

>After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

>Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...



## Questions:
1. What was the most likely IPv4 address of we8105desk on 24AUG2016?

2. Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.

3. What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

4. What was the first suspicious domain visited by we8105desk on 24AUG2016?

5. During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

6. What is the name of the USB key inserted by Bob Smith?

7. Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

8. How many distinct PDFs did the ransomware encrypt on the remote file server?

9. The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

10. The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

11. The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

12. Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?



## Starting the Investigate

Feeling more confident from scenario 1, lets move on to part 2!

### 1
Starting out, we know we need to look for "we8105desk" on August 24th 2016. You can set the date using the query or use the tool bar's built in feature.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_date.png">
</p>
Below, I will also provide a few images that will helps us here. On the left will be Windows EventID's and the right will be Sysmon EventID's:
<div id="event ids" align="center">
    <table>
	    <tr>
    	    <td style="padding:10px">
        	    <img src="/Scenarios/Screenshots/s2_winevents.png">
      	    </td>
            <td style="padding:10px">
            	<img src="/Scenarios/Screenshots/s2_sysmonids.png">
            </td>
        </tr>
    </table>
</div>
I was not certain is users are logging in locally or via RDP so I searched for both 4624 and 3. 4624 was mainly showing a process id. Got what I was looking for using EventID=3.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_sourceip.png">
</p>



### 2
The question lets you know to go straight to suricata logs. Added cerber and checked the interesting fields for signature id and was able to use stats.
```
index=botsv1 sourcetype=suricata cerber
| stats count by alert.signature_id
```
<p align="center">
    <img src="/Scenarios/Screenshots/s2_lowsigid.png">
</p>



### 3
From my network experience, I know that DNS uses A records and will point something human readable to an IP address. We got the source IP from question 1. Without adding "cerber" or "cerber*", there were 46 results. You could also add to the query to disregard well known domains to narrow it down if cerber wasn't part of the dns record.
```
NOT (query{}=*.microsoft.com OR query{}=*.google.com OR query{}=*.waynecorpinc.com)
```
<p align="center">
    <img src="/Scenarios/Screenshots/s2_fqdn.png">
</p>
As you can see, it lowered the results down to 36; which I could take down even farther by adding the ".local" but just want to show how you can filter out results.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_fqdn2.png">
</p>



### 4
For question 4, I added a few more options to help filter out some more DNS entries. 
<p align="center">
    <img src="/Scenarios/Screenshots/s2_sus.png">
</p>



### 5
To start, I just used vbs in the query and checked the source fields.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_vbs1.png">
</p>
I thought this was the way to go but wasted some time. Later, finally looked at the Sysmon logs with the following:

```
index=botsv1 source=WinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk vbs
```

I can see a few things that stand out.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_vbscl.png">
</p>
Since the question is asking about it launching from ".exe" and asking about length, I (against everything in me) disregarded the "decrypt my files" and tried to find the length of the other command.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_vbslen.png">
</p>



### 6
After some research, Windows Registry uses friendlyname for USB's. Used that to generate a query and looked around in the fields. Data showed MIRANDA_PRI.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_usb.png">
</p>



### 7
I had a few options on this one. I decided to search for the destination port of 445(smb) since it's for fileshares. Setting the host and looking for the destination, I was able to find the IP and server name.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_smbip.png">
</p>
<p align="center">
    <img src="/Scenarios/Screenshots/s2_smbsvr.png">
</p>



### 8
I wasted a bit of time on this one. I searched for the host being "we9041srv" and "pdf". It had some hits but being able to figure out how many files were encrypted was tricky. There wasn't anything that was out right saying encrypted. Finally saw accesses and files were deleted. Poking around more, I found relative target name.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_pdfs.png">
</p>



### 9
We know that Bob is using "we8105desk" and that script ran using the command line. If we look back at question 1, I shared an image of Event ID's and 1 is "Process Create". Sort by time so we have the initial process and parent ID's.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_pid.png">
</p>



### 10
The Sysmon Event ID list on question 1 shows Event ID 2 is for file creation. From the question, we are looking for .txt files in Bob's Windows profile. In the fields we can see TargetFileName. We can break that down into how many text files are seen.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_txt.png">
</p>



### 11
Looking at the Fortigate UTM, we can see the messages it gave from Bob's traffic. The single instance that stood out to me was "File is infected". 
<p align="center">
    <img src="/Scenarios/Screenshots/s2_msg.png">
</p>
Isolating that event, we can see the URL along with the file that was downloaded.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_mhtr.png">
</p>



### 12
From my studies of Comptia Security+, we know that you can hide data in an image without ruining the image. This process is called Steganography.

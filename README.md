# Splunk-Deployment & Threat-Detection-Lab
# About
 This repository is dedicated to hosting personal comprehensive walkthrough solutions for Splunk's Boss of the SOC (BOTS) CTF-style labs. 
 
 To be eventually updated with all BOTS events.

 
 # Walkthroughs
 
 - [Splunk BOTSv1](https://github.com/chan2git/splunk-bots/tree/main/botsv1) (completed) :white_check_mark:

What was the most likely IPv4 address of we8105desk on 24AUG2016?
First off I wanted to know what sort of data had been ingested into Splunk. With the search command below I found all the source types I needed for the CTF.

| metadata type=sourcetypes index="botsv1"

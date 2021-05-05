# OSCP-Human-Guide

**Edit**
I'm currently moving all the OSCP stuff and other things to my "[pentest-book](https://six2dez.gitbook.io/pentest-book/)". This repository will not have more updates. Sorry for the inconvenience.

**This page is the jouney with some tips, the real guide is [HERE](https://github.com/six2dez/OSCP-Human-Guide/blob/master/oscp_human_guide.md)**



My own OSCP guide with some presents, my owncrafted [guide](https://github.com/six2dez/OSCP-Human-Guide/blob/master/oscp_human_guide.md) and my Cherrytree [template](https://github.com/six2dez/OSCP-Human-Guide/blob/master/final_cherrytree_template.ctd), enjoy and feel free to contribute :)

Table of Contents
=================

   * [OSCP-Human-Guide](#oscp-human-guide)
      * [Intro - Before OSCP](#intro---before-oscp)
         * [Penetration Testing Book](#penetration-testing-book)
         * [HackTheBox (the easiest ones) and VulnHub](#hackthebox-the-easiest-ones-and-vulnhub)
      * [Course and Lab](#course-and-lab)
         * [Lab machines step-by-step](#lab-machines-step-by-step)
      * [Exam preparation (after labs)](#exam-preparation-after-labs)
         * [HackTheBox(VIP) and VulnHub (medium ones)](#hacktheboxvip-and-vulnhub-medium-ones)
         * [Exam mockups](#exam-mockups)
            * [First mockup:](#first-mockup)
            * [Second mockup](#second-mockup)
            * [Third mockup](#third-mockup)
            * [Fourth mockup](#fourth-mockup)
      * [Exam first try](#exam-first-try)
         * [Preparations](#preparations)
         * [Result](#result)
      * [1 extra lab month](#1-extra-lab-month)
      * [Exam second try](#exam-second-try)
         * [Preparations](#preparations-1)
         * [Result](#result-1)

## Intro - Before OSCP

### Penetration Testing Book

It was an incredible help to me, I have it on the throne of pentesting basis, litte outdated: https://nostarch.com/pentesting, there is some info to get all the exercises with updated resources here: https://github.com/PollyP/Notes-on-Penetration-Testing-A-Hands-On-Guide-to-Hacking/blob/master/README.md

### HackTheBox (the easiest ones) and VulnHub

## Course and Lab

Repeat this mantra: **Sleep, rest, calm down you will get it**

### Lab machines step-by-step

This is a must: **Use only the VM provided for this course, not the Kali latest ISO** 
I did it with the PWK VM upgrading only MSF, Nmap, Nikto and the basics, but **not** upgrade the entire OS.

1. Open CherryTree template to take screenshots and paste outputs.
2. Run simple nmap and then the slower.
3. Check first results (webs, ssh, ftp) from the first fast nmap scan.
4. Review slower nmap scan.
5. Always go for the easiest port (SMB, FTP, HTTP...).
6. Depend on each port do the appropiate enumeration techniches.
7. Time to find exploits and try them.
   1. In case webpage is your target, look the source code, ever, will find software versions, for example.
8. When you get the exploit and you have tweaked it for your target and purpose you should be inside as low user.
9. Simple enumeration such as OS version, users, permissions, files in home, compilers, available tools.
   - In case of Windows, with `systeminfo` is enough for me https://github.com/GDSSecurity/Windows-Exploit-Suggester
10. Find out how to upload files.
11. Upload your privilege escalation script.
    1. In case of Linux I always used LinEnum and linux-exploit-suggester
    2. Check services running and check the strange ones in [gtfobins](https://gtfobins.github.io/) or [lolbas](https://lolbas-project.github.io/#) and [exploit-db](https://www.exploit-db.com/)
12. Run your exploit and get root, collect proofs, passwords, review root paths and home paths for interesting files for other machines.

## Exam preparation (after labs)

### HackTheBox(VIP) and VulnHub (medium ones)

### Exam mockups

I did 4 exam mockups in 2 weeks, yes, 24 hours for 5 machines. Main resource to choose machines: [NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8)

#### First mockup:

- Brainpan [VulnHub](https://www.vulnhub.com/entry/brainpan-1,51/)
- Kioptrix2014 [VulnHub](https://www.vulnhub.com/entry/kioptrix-2014-5,62/)
- Lordoftheroot [VulnHub](https://www.vulnhub.com/entry/lord-of-the-root-101,129/)
- Pwnlab_init [VulnHub](https://www.vulnhub.com/entry/pwnlab-init,158/)
- VulnOsv2 [VulnHub](https://www.vulnhub.com/entry/pwnlab-init,158/)

#### Second mockup

- Bastard [HTB](https://www.hackthebox.eu/home/machines/profile/7)
- Blue [HTB](https://www.hackthebox.eu/home/machines/profile/51)
- Conceal [HTB](https://www.hackthebox.eu/home/machines/profile/168)
- Devel [HTB](https://www.hackthebox.eu/home/machines/profile/3)
- Metasploitable3_windows [GitHub](https://github.com/rapid7/metasploitable3)
- Silo [HTB](https://www.hackthebox.eu/home/machines/profile/131)

#### Third mockup

- LazySysadmin [VulnHub](https://www.vulnhub.com/entry/lazysysadmin-1,205/)
- Metasploitable3_ubuntu [GitHub](https://github.com/rapid7/metasploitable3)
- MrRobot [VulnHub](https://www.vulnhub.com/entry/mr-robot-1,151/)
- Pinky's Palace v1 [VulnHub](https://www.vulnhub.com/entry/pinkys-palace-v1,225/)
- Own crafted Windows XP machine with SLMail, Minishare, DoStackOverflowGood, VulnServer and WarFTPD.

#### Fourth mockup

- Active [HTB](https://www.hackthebox.eu/home/machines/profile/148)
- Bounty [HTB](https://www.hackthebox.eu/home/machines/profile/142)
- Brainpan [VulnHub](https://www.vulnhub.com/entry/brainpan-1,51/)
- Cronos [HTB](https://www.hackthebox.eu/home/machines/profile/11)
- DevOops [HTB](https://www.hackthebox.eu/home/machines/profile/140)

## Exam first try

### Preparations

- Session recorded with OBStudio, two screens without sound at 10 fps in mkv format, about 25GB.

### Result

Failed, 6 hours in the first BOF, all went bad due my extreme nervous :(

## 1 extra lab month

After this last month this was my result: IT Network unlocked, 32 machines rooted in Public Network, that's all. No exam mockups.

## Exam second try

### Preparations

- Session recorded with OBStudio, two screens without sound at 10 fps in mkv format, about 25GB.

### Result

- After 8 hours 4 machines rooted. After 20 hours 5 machines rooted, with 5 slept.
- [This](https://github.com/whoisflynn/OSCP-Exam-Report-Template) is the template used for my exam report.
- Report done in 4 hours.

## Stargazers over time

[![Stargazers over time](https://starchart.cc/six2dez/OSCP-Human-Guide.svg)](https://starchart.cc/six2dez/OSCP-Human-Guide)  










# KnockKnock - v1.1 

#### Please make sure to actually utilize the README. 

Designed to validate potential usernames by querying OneDrive and/or Microsoft Teams, which are passive methods.  
It can output/create a list of legacy Skype users identified through Microsoft Teams enumeration.
It can also get details from Teams, such as availability, device type, and out of office message.
Finally, it also creates a nice clean list for future usage, all conducted from a single tool.  

## v1.1 Update's
- Reiterate that the `-t proxy` option will get the token for you. This deffinatly works on a Kali GUI desktop. Microsoft keeps changing, and the location of the token moves, so this is the safest way to sureley grab it. 
- Threads has been fixed... again... and now handels threads a lot better.
- Token parser has been updated to work better. 
- Garbage output from the interactive firefox option has been muted. 

## v1.0 Update's
- If you cant get the token normally, you can use `-t proxy` to have a selenium firefox browser open on your system, where you login to your MS account, and it grabs the token for you before exiting and continuing the enumeration. 
- Progress bar has been added to let you know whats going on.
- Threads has been fixed so now changing the threads will actually speed things up.
- Added logging, detailed output is now available.

------------------------------------------------------------------------------------
# Options
- If there is an error when using the proxy, you can ignore the error, it will continue to work correctly, its from an issue with a python package. (seems to be fixed)
- You can select one or both modes, as long as the appropriate options are provided for the modules selected.
- When running both OneDrive and Teams enumeration, it will remove verified users from the first function as to not check them again in the second function. 
- Both modules will require the domain flag (-d) and the user input list (-i).  
- The tool does not require an output file as an option, and if not supplied, it will print to screen only.  
- Verbose mode outputs a lot of data, but even more so when using the proxy. You have been warned.
- The Teams option requires a bearer token. The script automatically parses the token to get whats needed for authentication. (highly recommend the `-t proxy` option to get the token)  
- The LEGACY (-l) option shows users that still have SkypeID settings and will write it to a seperate file (Output option (-o) required).
- The STATUS (-s) option shows user teams availability, device, and OutOfOffice message, then writes it to a seperate file (Output option (-o) required). 

------------------------------------------------------------------------------------

# Usage

```
  _  __                 _    _  __                 _
 | |/ /_ __   ___   ___| | _| |/ /_ __   ___   ___| | __
 | ' /| '_ \ / _ \ / __| |/ / ' /| '_ \ / _ \ / __| |/ /
 | . \| | | | (_) | (__|   <| . \| | | | (_) | (__|   <
 |_|\_\_| |_|\___/ \___|_|\_\_|\_\_| |_|\___/ \___|_|\_\\
    v1.1                                  @waffl3ss

usage: KK_Dev.py [-h] [--teams] [--onedrive] [-l] [-s] -i INPUTLIST [-o OUTPUTFILE] -d TARGETDOMAIN [-t TEAMSTOKEN] [--threads MAXTHREADS] [-v]

options:
  -h, --help            show this help message and exit
  --teams               Run the Teams User Enumeration Module
  --onedrive            Run the One Drive Enumeration Module
  -l                    Write legacy skype users to a seperate file
  -s                    Write Teams Status for users to a seperate file
  -i INPUTLIST          Input file with newline-seperated users to check
  -o OUTPUTFILE         Write output to file
  -d TARGETDOMAIN       Domain to target
  -t TEAMSTOKEN         Teams Token, either file, string, or 'proxy' for interactive Firefox
  --threads MAXTHREADS  Number of threads to use in the Teams User Enumeration (default = 10)
  -v                    Show verbose errors
```
### Examples

```
./KnockKnock.py -teams -i UsersList.txt -d Example.com -o OutFile.txt -t BearerToken.txt
./KnockKnock.py -teams -i UserList.txt -d Example.com -o OutFile.txt -t proxy
./KnockKnock.py -onedrive -i UsersList.txt -d Example.com -o OutFile.txt
./KnockKnock.py -onedrive -teams -i UsersList.txt -d Example.com -t BearerToken.txt -l
```

------------------------------------------------------------------------------------
# References

[@nyxgeek](https://github.com/nyxgeek) - [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum)  
[@immunIT](https://github.com/immunIT) - [TeamsUserEnum](https://github.com/immunIT/TeamsUserEnum)  

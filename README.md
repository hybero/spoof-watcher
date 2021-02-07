# Spoof Watcher
```
	  _________                     _____   __      __         __         .__                  
	 /   _____/_____   ____   _____/ ____\ /  \    /  \_____ _/  |_  ____ |  |__   ___________ 
	 \_____  \\____ \ /  _ \ /  _ \   __\  \   \/\/   /\__  \\   __\/ ___\|  |  \_/ __ \_  __ \
	 /        \  |_> >  <_> |  <_> )  |     \        /  / __ \|  | \  \___|   Y  \  ___/|  | \/
	/_______  /   __/ \____/ \____/|__|      \__/\  /  (____  /__|  \___  >___|  /\___  >__|   
	        \/|__|                                \/        \/          \/     \/     \/       


			    |---::[ Spoof Watcher ]::---|

|+ USAGE:

	[i] Scans network for ARP spoofers:

		./spoof_watcher.py


|+ PARAMETERS:

	-h, --help
		Show this help.



```

## Installation & Usage

Clone the repository:

```git clone https://github.com/hybero/spoof-watcher.git```

Cd into the directory:

```cd spoof-watcher/```

Install required libraries:

```pip3 install -r requirements.txt```

Run the script to send ARP spoofed packets:

```./spoof-watcher.py```

Script scans network for spoofers, alerts if finds any. Quit spoofing by pressing 'CTRL+C'.

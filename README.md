# CloudAVWizard
 An open source, second opinion cloud antivirus scanner
 
 Requirements:
	Python 2.7 https://www.python.org/downloads/
	Shove Module https://pypi.python.org/pypi/shove
	
 Usage:
	Install Clamwin and Emsisoft Emergency Kit
	Set paths in settings.conf
	Run CloudAVWizard_Core.py, CloudAVWizard_eek.py and CloudAVWizard_clamwin.py
	
	Each scanner should be run on its own virtual machine/physical machine.
	Multiple scanners can be run for each AV and scan tasks will be distributed between them
	

 An example web interface setup with usb webserver can be found in the example folder.
 You will need to change the path to python.exe if it is not located at c:\python27\python.exe
 
 Please report any errors https://github.com/bourkey08/CloudAVWizard/issues
#!c:/Python27/python.exe -u
#This is a (very mess) example of a basic interface for communicating with CloudAVWizard

import cgi, socket, os
import cgitb; cgitb.enable()  # for troubleshooting
import CloudAVWizard_API

try: # Windows needs stdio set for binary mode.
    import msvcrt
    msvcrt.setmode (0, os.O_BINARY) # stdin  = 0
    msvcrt.setmode (1, os.O_BINARY) # stdout = 1
except ImportError:
    pass

#Import API and create instance
api = CloudAVWizard_API.api()
api.setipport('192.168.1.117', 3841)

#Set Path To WebServer And Temp Folder
serverpath = 'http://127.0.0.1:8080'
tmpfolder = 'fsadf798sdanjisdhfs7d6rsdf'

#Make Sure Temp Folder Exists
if not os.path.exists(tmpfolder):
    os.mkdir(tmpfolder)

form = cgi.FieldStorage()

#Headers
print "Content-type: text/html"
print

#Send Output TO Browser
print '<html><head><title></title></head><body><center>'

#If Upload File
if form.has_key('fileToUpload'):
    tmpname = os.urandom(16).encode('hex')
    fileitem = form['fileToUpload']
    ext = fileitem.filename.rpartition('.')[2] 
    file(os.path.join(tmpfolder, tmpname + '.' + ext),'wb').write(form['fileToUpload'].file.read())
    hash1 = api.addfileurl(serverpath + '/' + tmpfolder + '/' + tmpname+'.' + ext)
    os.remove(os.path.join(tmpfolder, tmpname + '.' + ext))
    print '<meta http-equiv="refresh" content="0; url=index.py?filehash=' + hash1 + '" />'
    
elif form.has_key('filehash'):
    filehash = form.getvalue('filehash')
    results = api.results(filehash)
    if results:
        print 'Detection Ratio: ' + str(results[1][0]) + '/' +str(results[1][1]) + '<br><br>'
        print '<table cellpadding="4" border="1"><tr><td>Scanner</td><td>Infected</td><td>Infection Name</td></tr>'
        for item in results[2]:
            print '<tr><td>' + item[0] + '</td><td>' + str(item[1]) + '</td><td>' + item[2] + '</td></tr>' 
        print '</table><br><br>'
        print '<a href="index.py">New Scan</a>'
        
    else:#Results Not Ready        
        print 'Waiting On Results...<br><br>'
        stats = api.getstats()
        print 'Pending Jobs: ' + str(stats[0]) + '<br>'
        print 'Jobs In Progress: ' + str(stats[1]) + '<br>'
        print '<meta http-equiv="refresh" content="5">'
        
else:
    #Upload Form
    form = '''
    <center>
    <form action="index.py" method="post" enctype="multipart/form-data">
        Select File To Upload(max size 128MB):<br>
        <input type="file" name="fileToUpload" id="fileToUpload"><br>
        <input type="submit" value="Upload" name="submit"><br>
    </form>
    </center>
    '''
    print form


print '</center></body>'
print '</html>'

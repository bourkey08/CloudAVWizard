#CloudAVWizard, An open source, second opinion cloud antivirus scanner
#Copyright (C) 2016  Mitchell Bourke
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

import Queue, threading, time, socket, os, ConfigParser, CloudAVWizard_API, subprocess, re

#Code Shared By All Scanner Modules
#_________________________________________________________________________________________________________
def logger(log, config):
    if os.path.split(config.get('core', 'logpath'))[0] != '':#If Logging To Subfolder
        if not os.path.exists(os.path.split(config.get('core', 'logpath'))[0]):#If Not Subfolder Exists
            os.makedirs(os.path.split(config.get('core', 'logpath'))[0])#Create It
        
    while True:
        entry = log.get()#Get Entry, Waits here for next entry
        if config.getboolean('core', 'printlog'):#Print If Enabled
            print time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(time.time())) + ': ' + entry
            
        if config.getboolean('core', 'writelog'):#Write To Disk If Enabled
            with file(config.get('core', 'logpath'), 'a') as fil:
                fil.write(time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(time.time())) + ': ' + entry + '\n')
                fil.close()
    
#Load Config File
config = ConfigParser.ConfigParser()
config.read('settings.conf')

#Create Working Directory
if not os.path.exists(config.get('modules_global', 'workingdir')):
    os.makedirs(config.get('modules_global', 'workingdir'))

#Create Log Queue and start logger
log = Queue.Queue(maxsize=8192)
threading.Thread(target=logger, args=(log, config), name='Log Handler').start()

#Get an instance of api for talking to core
api = CloudAVWizard_API.scannerapi()
if config.get('core', 'ip') == 'auto':
    ip, port = api.findcore(config.getint('global', 'broadcastport'), 'SharedKeyGoesHere'), config.getint('global', 'scannerport')
else:
    ip, port = config.get('core', 'ip'), config.getint('global', 'scannerport')

api.setipport(ip, port)

#___________________________________________________________________________________________
    
#Set A Unique Name For This Scanner
api.setname('Emsisoft')

#Register with core
if api.register() != 'ok':
    print 'Unable to register with core, exiting'
    os._exit(0)

#Functions for talking to AV Engine
#___________________________________________________________________________________________________________________________________
def update():
    cmd = subprocess.Popen((config.get('modules_eek', 'pathtoscanner'), '/u'))
    cmd.wait()
    return True

def scanfile(filename):
    cmd = subprocess.Popen((config.get('modules_eek', 'pathtoscanner'), '/f=' + os.path.join(config.get('modules_global', 'workingdir'), filename)), stdout=subprocess.PIPE)
    cmd.wait()
    result = re.findall('detected: (.*?) ', cmd.stdout.read())
    if len(result) > 0:
        return result[0]
    else:
        return ''

#____________________________________________________________________________________________________________________________________

#Accepts jobs and preforms scanns
class worker(threading.Thread):
    def __init__(self, lock, api, config):
        threading.Thread.__init__(self)
        self.lock = lock
        self.api = api
        self.config = config
        
    def run(self):
        global log
        while True:
            self.lock.acquire()#Lock Self, Prevents update from running while a scan is running
            try:
                job = self.api.requestjob()#Request a job
                if job != 'nojob':
                    print job
                    #Download File
                    dstfil = file(os.path.join(self.config.get('modules_global', 'workingdir'), job), 'wb')
                    for block in self.api.getfile(job):
                        dstfil.write(block)
                    dstfil.close()

                    #If file not empty scan it
                    if not os.path.getsize(os.path.join(self.config.get('modules_global', 'workingdir'), job)) == 0:
                        result = scanfile(job)
                        self.api.returnjob(job.partition('.')[0], result)

                    #Remove Temp File
                    os.remove(os.path.join(self.config.get('modules_global', 'workingdir'), job))
                
                else:
                    time.sleep(self.config.getfloat('modules_global', 'pollinterval'))

            except Exception as e:
                log.put(e)
                
            finally:
                self.lock.release()

#Update AV and set last update
log.put('Doing Initial Update')
update()
lastupdate = time.time()

#Create a lock for each scanning thread
locks = []
for a in xrange(0, config.getint('modules_eek', 'scanningthreads')):
    locks += [threading.Lock()]        
        
#Start Workers
log.put('Starting Workers')
for lock in locks:
    worker(lock, api, config).start()
log.put('Running')

#Wait until its time to do an update. Then lock all threads and do update.
while True:
    #If Time To Update
    if lastupdate < time.time() - config.getfloat('modules_eek', 'updateinterval'):
        log.put('Starting Update')
        #Lock All Threads
        for lock in locks:
            lock.acquire()

        #Do Update
        try:
            update()
            lastupdate = time.time()
            
        #Release All Locks   
        finally:
            for lock in locks:
                lock.release()
        log.put('Update Complete')
    time.sleep(1)

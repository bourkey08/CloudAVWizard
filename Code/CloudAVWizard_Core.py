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

import Queue, threading, time, socket, os, ConfigParser, urllib2, json, hashlib, shutil
from shove import Shove
from multiprocessing.pool import ThreadPool

#General
#____________________________________________________________________________________________________
#Logging Function
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
#______________________________________________________________________________________________________

                
#Networking
#_____________________________________________________________________________________________________                
#Auto Discovery
def autodiscover(config):#Sends a packet periodically so that Scanners scan find us
    global log
    ip, port = config.get('core', 'ip'), config.getint('global', 'broadcastport')
    if ip == 'auto':
        ip = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    log.put('Broadcasting on: ' + ip + ':'+str(port))
    while True:
        sock.sendto(config.get('global','sharedkey'), ('<broadcast>', config.getint('global', 'broadcastport')))
        time.sleep(config.getfloat('advanced_core','broadcastinterval'))

#Scanner Requests
class ScannerConnect(threading.Thread):
    def __init__(self, config, jobs, jobslock, scanners, resultcache, resultcachelock):
        threading.Thread.__init__(self)
        self.config = config
        self.tpool = ThreadPool(processes=self.config.getint('advanced_core','scannerthreadcount'))
        self.scanners = scanners#List of scanners
        #Format for each job is, filehash: {ext: string, timeadded: float, scanners: [scanner1: {scanned: True/False, scaninprogress: True/False, clean: True/False, infectionname: string}, scanner2: {ect}]}
        self.jobs = jobs
        self.lock = jobslock
        self.resultcache = resultcache
        self.resultcachelock = resultcachelock

    #Create server, runs in its own thread
    def run(self):
        global log
        ip, port = self.config.get('core', 'ip'), self.config.getint('global', 'scannerport')
        if ip == 'auto':
            ip = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind((ip, port))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            self.tpool.apply_async(self.connectionhandler, args=(conn, addr))
    
    def connectionhandler(self, conn, addr):
        instruction = conn.recv(512).split(' ')
        if instruction[0] == 'requestjob':
            job = self.requestjob(instruction[1])
            conn.send(job)
                
        elif instruction[0] == 'returnjob':
            conn.send('ok')
            infection = conn.recv(4096)
            self.updatejob(instruction[1], instruction[2], infection)
            
        elif instruction[0] == 'getfile':
            for block in self.getfile(instruction[1]):
                conn.send(block)
                
        elif instruction[0] == 'register':            
            self.addscanner(instruction[1])
            conn.send('ok')
            
        else:
            conn.send('Invalid Request')
        conn.close()

    
    #Check for any pending jobs that have not been scanned by this scanner, if none and maxjobsinprogress not exceeded fetch a new job from toscan.
    def requestjob(self, scanner):
        if scanner not in self.scanners:
            return 'notregistered'
        
        self.lock.acquire()#Get lock so we can work with jobs dict        
        try:
            #Iterate through job queue and check for any that have not been scanned/allocated to this scanner
            for job in self.jobs.iterkeys():
                if self.jobs[job]['scanners'].has_key(scanner):#If scanner was registered when job was submitted
                    if self.jobs[job]['scanners'][scanner]['scanned'] == False and self.jobs[job]['scanners'][scanner]['scaninprogress'] == False:#If job has not been scanned by this scanner
                        self.jobs[job]['scanners'][scanner]['scaninprogress'] = True
                        return job + self.jobs[job]['ext']

            return 'nojob'

        finally:#Release lock even on error
            self.lock.release()


    def updatejob(self, scanner, filehash, infection):
        self.lock.acquire()#Get lock so we can work with jobs dict
        try:
            if infection == 'clean':
                self.jobs[filehash]['scanners'][scanner]['clean'] = True
                self.jobs[filehash]['scanners'][scanner]['infectionname'] = ''
            else:
                self.jobs[filehash]['scanners'][scanner]['clean'] = False
                self.jobs[filehash]['scanners'][scanner]['infectionname'] = infection
            self.jobs[filehash]['scanners'][scanner]['scanned'] = True
            
        finally:#Release lock even on error
            self.lock.release()
        return True
    
    def getfile(self, filename):#Generator, iterates over file
        blocksize = self.config.getint('advanced_global','sockchunksize')
        filepath = os.path.join(self.config.get('core', 'workingdir'), 'PendingSamples', filename)
        if not os.path.exists(filepath):
            yield 'no'
        else:
            yield 'ok'
            with file(filepath, 'rb') as fil:
                block = fil.read(blocksize)
                while block != '':
                    yield block                    
                    block = fil.read(blocksize)

    def addscanner(self, scanner):
        if scanner not in self.scanners:#If Not Already Present
            self.scanners += [scanner]#Add It
            
            #Need to flush result cache as cached results will not have been scanned with new scanner
            self.resultcachelock.acquire()
            try:
                resultcache.clear()
            finally:
                self.resultcachelock.release()
                
#JobManager
class JobsManager(threading.Thread):    
    def __init__(self, config, jobs, jobslock, scanners, resultcache, resultcachelock, toscan):
        threading.Thread.__init__(self)
        self.config = config
        self.jobs = jobs
        self.jobslock = jobslock
        self.scanners = scanners
        self.resultcache = resultcache
        self.resultcachelock = resultcachelock
        self.toscan = toscan
        
    #Loops through jobs, any that have been scanned by all scanners are removed and results added to resultcache
    #If len(jobs) < maxjobsinprogress fill jobs from toscan queue.
    def run(self):
        global log
        while True:
            time.sleep(self.config.getfloat('advanced_core','jobmanagerinterval'))
            self.jobslock.acquire(), self.resultcachelock.acquire()
            try:
                #If maxjobsinprogress not exceeded, attempt to fill jobs from toscan.
                while len(self.jobs.keys()) < self.config.getint('advanced_core', 'maxjobsinprogress'):
                    try:
                        #Build New Job
                        filehash, ext = self.toscan.get_nowait()
                        newjob = {}
                        newjob['ext'] = ext
                        newjob['timeadded'] = time.time()
                        newjob['scanners'] = {}
                        #For Each Scanner, Add a blank entry
                        for scanner in self.scanners:
                            newjob['scanners'][scanner] = {'scanned': False, 'scaninprogress': False, 'clean': True, 'infectionname': ''}
                        self.jobs[filehash] = newjob
                    except:#No More Entrys in toscan
                        break

                #If job completed or time expired, remove job and put results in resultcache
                jobstodelete = []
                for filehash in self.jobs.iterkeys():
                    jobdone = False
                    #If Expired
                    if self.jobs[filehash]['timeadded'] < time.time() - self.config.getint('advanced_core', 'jobinprogresstimeout'):
                        jobdone = True
                        
                    else:#Check if scan has completed for all scanners
                        allfinished = True
                        for scanner in self.jobs[filehash]['scanners']:
                            if self.jobs[filehash]['scanners'][scanner]['scanned'] != True:
                                allfinished = False
                            
                        if allfinished:
                            jobdone = True
                        del allfinished

                    #Add job results to resultcache and then delete job
                    if jobdone:
                        result = {'scantime': time.time(),'clean': True, 'summary': (), 'details': []}

                        #Loop through scanners, add results to details and calculate infected count and scannedcount
                        infectedcount = 0
                        avscannedcount = 0
                        for scanner in self.jobs[filehash]['scanners'].iterkeys():
                            if self.jobs[filehash]['scanners'][scanner]['scanned']:#If Scanner Has Scaned File
                                avscannedcount += 1
                                if self.jobs[filehash]['scanners'][scanner]['clean']:#If Scanner Did not find any infections
                                    result['details'] += [(scanner, False, '')]
                
                                else:#Scanner Found infection
                                    infectedcount += 1
                                    result['details'] += [(scanner, True, jobs[filehash]['scanners'][scanner]['infectionname'])]

                        #Add Summary To result
                        result['summary'] = (infectedcount, avscannedcount)

                        #Add To ResultCache
                        self.resultcache[filehash] = result

                        #Delete From Jobs
                        jobstodelete += [filehash]

                        log.put('Scanning Completed: ' + filehash)

                #Delete Finished Jobs
                for filehash in jobstodelete:
                    #Delete the actual file
                    filename = filehash + jobs[filehash]['ext']
                    if self.config.get('','').lower() == 'true':
                        shutil.copy(os.path.join(self.config.get('core', 'workingdir'), 'PendingSamples', filename),os.path.join(self.config.get('core', 'workingdir'), 'PositveSamples', filename))
                    os.remove(os.path.join(self.config.get('core', 'workingdir'), 'PendingSamples', filename))
                    
                    #Delete From Jobs
                    del self.jobs[filehash]
                        
            except Exception as e:
                log.put('Error In Job Manager: ' + str(e))
                
            finally:
                self.jobslock.release(), self.resultcachelock.release()
            

#WebserverConnect, Handles connections from webserver for submitting and fetching results.
class WebserverConnect(threading.Thread):
    def __init__(self, config, resultcache, resultcachelock, toscan, jobs, jobslock, scanners):
        threading.Thread.__init__(self)
        self.config = config
        self.resultcache = resultcache
        self.resultcachelock = resultcachelock
        self.toscan = toscan
        self.jobs = jobs
        self.jobslock = jobslock
        self.scanners = scanners
        self.tpool = ThreadPool(processes=self.config.getint('advanced_core','webserverthreadcount'))
        
    #Create server, runs in its own thread
    def run(self):
        global log
        ip, port = self.config.get('core', 'ip'), self.config.getint('global', 'apiport')
        if ip == 'auto':
            ip = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind((ip, port))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            self.tpool.apply_async(self.connectionhandler, args=(conn, addr))

    def connectionhandler(self, conn, addr):
        instruction = conn.recv(512).split(' ')
        if instruction[0] == 'addfileurl':
            conn.send(self.addfile(url=instruction[1]))
            
        elif instruction[0] == 'addfilelocal':
            conn.send(self.addfile(path=instruction[1]))
            
        elif instruction[0] == 'results':
            conn.send(json.dumps(self.getscanresults(instruction[1])))
            
        elif instruction[0] == 'getstats':
            conn.send(self.getstats())
            
        else:
            conn.send('Invalid Request')
        conn.close()
        
    #Get Statistics, jobsinquecount, jobsinprogress, scannerslist
    def getstats(self):
        global log
        self.jobslock.acquire()
        try:
            toscansize = self.toscan.qsize()
            jobssize = len(self.jobs.keys())
            scannerssize = len(scanners)
            return str(toscansize) + ' ' + str(jobssize) + ' ' +str(scannerssize)
        finally:
            self.jobslock.release()
    
    #Return Results Of A Completed Scan
    def getscanresults(self, filehash):
        self.resultcachelock.acquire()
        try:
            if filehash in self.resultcache.keys():
                #If Scan Was Completed less than rescaninterval in minutes ago
                if self.resultcache[filehash]['scantime'] > time.time() - (self.config.getfloat('core', 'rescaninterval') * 60):
                    #Clean is True if 0 positives otherwise false, summary is turple (infected, total scanned with), List Of turples [(av, infected T/F, Infection)]
                    return (self.resultcache[filehash]['clean'], self.resultcache[filehash]['summary'], self.resultcache[filehash]['details'])
                else:
                    return False
            else:
                return False        
        finally:
            self.resultcachelock.release()
            
    #Add File To To Be Scanned Queue Either From A Local Path Or A Url
    def addfile(self, path='', url=''):
        #Load File Into Temp Location Under Temp Name
        #Calculate hash while copying
        self.jobslock.acquire(), self.resultcachelock.acquire()
        try:
            tmpname = os.urandom(20).encode('hex')
            hashobj = hashlib.sha1()
            if path != '':#Local Path Specified, Used For Testing Or Where WebServer Is On Same PC as Core
                if os.path.exists(path):
                    #Read file in block size incremends and copy to Destination, update hash object with each block
                    srcfil = file(path, 'rb')
                    dstfil = file(os.path.join(self.config.get('core', 'workingdir'), 'Temp', tmpname), 'wb')
                    block = srcfil.read(self.config.getint('advanced_core', 'fileblocksize'))
                    while block != '':
                        dstfil.write(block)
                        hashobj.update(block)
                        block = srcfil.read(self.config.getint('advanced_core', 'fileblocksize'))
                    dstfil.close()
                    srcfil.close()
                    extension = os.path.splitext(path)[1]
                else:
                    return 'error'
                
            elif url != '':#If Url Specified
                try:
                    srcfil = urllib2.urlopen(url)
                    dstfil = file(os.path.join(self.config.get('core', 'workingdir'), 'Temp', tmpname), 'wb')
                    block = srcfil.read(self.config.getint('advanced_core', 'fileblocksize'))
                    while block != '':
                        dstfil.write(block)
                        hashobj.update(block)
                        block = srcfil.read(self.config.getint('advanced_core', 'fileblocksize'))
                    dstfil.close()
                    srcfil.close()
                    extension = '.' + url.rpartition('.')[2]
                except Exception as e:
                    return 'error'
            else:
                return 'error'

            #Move file to PendingSamples, Add To Que & Return hash
            filehash = hashobj.hexdigest()
            
            #If Already Scanned And At Least 15 Mins From Expiring
            if filehash in self.resultcache.keys():
                if self.resultcache[filehash]['scantime'] - 900 > time.time() - (self.config.getfloat('core', 'rescaninterval') * 60):
                    os.remove(os.path.join(self.config.get('core', 'workingdir'), 'Temp', tmpname))
                    return filehash

            #If Already in Que
            if os.path.exists(os.path.join(self.config.get('core', 'workingdir'), 'PendingSamples', filehash+extension)):
                os.remove(os.path.join(self.config.get('core', 'workingdir'), 'Temp', tmpname))
                return filehash

            try:
                os.path.join(self.config.get('core', 'workingdir'), 'PendingSamples', tmpname+extension)
                os.rename(os.path.join(self.config.get('core', 'workingdir'), 'Temp', tmpname), os.path.join(self.config.get('core', 'workingdir'), 'PendingSamples', filehash  + extension))
                self.toscan.put((filehash, extension))
            except:
                log.put('Error Moving File To PendingSamples: ' + filehash + extension)
                return 'error'
            
            return filehash

        except Exception as e:
            return 'error'
        
        finally:
            self.jobslock.release()
            self.resultcachelock.release()
    
#Remove expired entrys from resultcache
class ResultCacheManager(threading.Thread):
    def __init__(self, resultcache, resultcachelock, config):
        threading.Thread.__init__(self)
        self.config = config
        self.resultcache = resultcache
        self.resultcachelock = resultcachelock
        
    def run(self):
        while True:
            time.sleep(self.config.getfloat('advanced_core', 'resultmanagerinterval'))
            self.resultcachelock.acquire()
            try:
                todelete = []
                for filehash in resultcache.iterkeys():#For Each Result
                    #If Expired
                    if resultcache[filehash]['scantime'] < time.time() - self.config.getfloat('core', 'rescaninterval'):
                        todelete += [filehash]

                for filehash in todelete:
                    del resultcache[filehash]
                    
            finally:
                self.resultcachelock.release()
            
        

#______________________________________________________________________________________________________


#Startup
#______________________________________________________________________________________________________
    
#Load Config File
config = ConfigParser.ConfigParser()
config.read('settings.conf')

#Create Folders
folders = [config.get('core', 'workingdir')]
folders += [os.path.join(config.get('core', 'workingdir'), 'PendingSamples')]
folders += [os.path.join(config.get('core', 'workingdir'), 'PositveSamples')]
folders += [os.path.join(config.get('core', 'workingdir'), 'Temp')]

for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)
        
#Create To Scan Queue
toscan = Queue.Queue(config.get('advanced_core','scanquesize'))#Que For Files To Scan, This Is Split Up Into Queues per scanner

#Create Result Cache, File outpreforms dbm by 20x which out preforms lite by 5x
resultcachelock = threading.Lock()
resultcache = Shove('file://' + os.path.join(config.get('core', 'workingdir'), 'ResultsCache.db'), 'memory')

#Create Log Queue and start logger
log = Queue.Queue(maxsize=config.get('advanced_core','logquesize'))
threading.Thread(target=logger, args=(log, config), name='Log Handler').start()

#Start Auto Discover
threading.Thread(target=autodiscover, args=(config,), name='Auto Discover Broadcast').start()

#Start ScannerConnect Server and JobManager
jobs = {}
jobslock = threading.Lock()
scanners = []
ScannerConnect(config, jobs, jobslock, scanners, resultcache, resultcachelock).start()
JobsManager(config, jobs, jobslock, scanners, resultcache, resultcachelock, toscan).start()

#Start Webconnect Server
WebserverConnect(config, resultcache, resultcachelock, toscan, jobs, jobslock, scanners).start()

#Start Result Cache Manager
ResultCacheManager(resultcache, resultcachelock, config).start()
#______________________________________________________________________________________________________


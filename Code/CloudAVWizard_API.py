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

#Api for connecting and interface to CloudAVWizard.
import socket, time, json

#Api for interfaces to connect to core
#Must call setipport before any other functions
class api():
    def setipport(self, ip, port):
        self.ip = ip
        self.port = port
        return True

    #Returns Stats    
    def getstats(self):        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('getstats')
        result = s.recv(4096)
        s.close()
        return result.split(' ')

    #Adds a file using local paths, local path must be relative to core.
    def addfilelocal(self, path):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('addfilelocal ' + path)
        hash1 = s.recv(4096)
        s.close()
        if hash1 == 'error':
            return False
        else:
            return hash1

    #Add a file by url
    def addfileurl(self, url):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('addfileurl ' + url)
        hash1 = s.recv(4096)
        s.close()
        if hash1 == 'error':
            return False
        else:
            return hash1

    #Return results or [False] if results not available for hash
    def results(self, filehash):       
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('results ' + filehash)
        result = s.recv(4096)
        s.close()
        return json.loads(result)

#API for scanners to connect to core
class scannerapi():
    
    #Listens on port for broadcast to locate core, returns ip
    def findcore(self, port, sharedkey, ip=''):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, port))
        while True:
            data, addr = s.recvfrom(1024)
            if data == sharedkey:
                break
        s.close()
        return addr[0]

    #Must be called before anything except findcore
    def setipport(self, ip, port):
        self.ip = ip
        self.port = port
        return True
    
    #Sets Scanner Name, Must be called before any interaction with core
    def setname(self, scannername):
        self.scannername = scannername
        return True

    #Register a scanner with core
    def register(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('register ' + self.scannername)
        output = s.recv(4096)
        s.close()
        return output

    #Request a new job, will return nojob, notregistered or hash.ext
    def requestjob(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('requestjob ' + self.scannername)
        job = s.recv(4096)
        s.close()
        return job

    #Return result of scan to core
    def returnjob(self, filehash, infection=''):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('returnjob ' + self.scannername + ' ' + filehash)
        s.recv(4096)
        if infection == '':
            s.send('clean')
        else:
            s.send(infection)
        s.close()
        return True

    #Generator for downloading files
    def getfile(self, filename):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send('getfile ' + filename)
        if s.recv(2) == 'ok':
            block = s.recv(4096)
            while block:
                yield block
                block = s.recv(4096)
        s.close()
    
api = scannerapi()
ip = api.findcore(3843, 'SharedKeyGoesHere')

import os
from http.server import BaseHTTPRequestHandler, HTTPServer

class rqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        

def make():
    server = HTTPServer('0.0.0.0', 1234)
    server.serve_forever()
    print("Server Running.")
    upload()

def upload():
    os.system(r""".\sysinternals\psexec.exe \\192.168.18.149 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.1\Scripts\upload\* C:\\Users\Administrator\\Scripts'""")
    print("Copying scripts.")
    os.system(r""".\sysinternals\psexec.exe \\192.168.18.149 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command 'Import-Module C:\\Users\Administrator\\Scripts; Invoke-ADGen -All:$true'""")


if __name__ == "__main__":
    make()
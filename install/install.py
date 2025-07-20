import os
import threading
semaphore = threading.Semaphore(4)
def main():
    f = open("ip.txt", "r")
    ip = f.read().strip()
    a = open("setup.txt", "r")
    while True:
        try:
            cmd = a.readline()
            cmd = cmd.replace("$dcip", ip)
            if (cmd == ""):
                break
            else:
                threading.Thread(target=run, args=(cmd, )).start()
        except:
            break

def run(cmd):
    semaphore.acquire()
    try:
        os.system(cmd)
    finally:
        semaphore.release()
        
if __name__  == "__main__":
    main()
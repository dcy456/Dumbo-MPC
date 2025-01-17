import subprocess
import sys

def Start_offline(n , id):

    # print(num , id)
    offline_command = ['python','-m','honeybadgermpc.offline_change']
    args = ["-d", "-f", f"conf/mpc_{n}/local.{id}.json" ]


    # Open a file for each log
    logfile = open(f'./log/logs-{id}.log', 'w')

    # Start process
    # subprocess.run(offline_command + args,  check=True , shell=True, start_new_session=True, stdout=logfile, stderr=subprocess.STDOUT)


    subprocess.run(offline_command + args,check=True ,  stdout=logfile )
    # subprocess.run(offline_command + args,check=True)
    logfile.close()




if __name__ == "__main__":

    num = 4
    id = sys.argv[1] 

    Start_offline(num, id)
    

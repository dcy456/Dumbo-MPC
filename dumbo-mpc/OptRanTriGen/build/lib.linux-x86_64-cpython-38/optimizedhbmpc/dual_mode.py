import asyncio
import time
import logging
from optimizedhbmpc.field import GF
from optimizedhbmpc.elliptic_curve import Subgroup
from optimizedhbmpc.polynomial import EvalPoint, polynomials_over
from optimizedhbmpc.reed_solomon import EncoderFactory, DecoderFactory
from optimizedhbmpc.mpc import Mpc
from optimizedhbmpc.utils.misc import (
    wrap_send,
    transpose_lists,
    flatten_lists,
    subscribe_recv,
)
from optimizedhbmpc.field import GF
from optimizedhbmpc.elliptic_curve import Subgroup
from optimizedhbmpc.broadcast.commoncoin import shared_coin
from optimizedhbmpc.broadcast.numberagreement import binaryagreement
from optimizedhbmpc.optrantrigen import OptRanTriGen

class HyperInvMessageType(object):
    SUCCESS = True
    ABORT = False

class dualmode:
    def __init__(self, pbk, pvk, n, t, my_id, k, send, recv):
        """
        Initialize the DualMode class.

        :param pbk: Public key for encryption (shared among participants).
        :param pvk: Private key for decryption (specific to the participant).
        :param n: Total number of participants in the computation.
        :param t: Fault tolerance threshold (max number of faulty participants).
        :param my_id: Unique identifier for the current participant (0 to n-1).
        :param k: Number of cryptographic triples to generate.
        :param send: Function to send messages to other participants.
        :param recv: Function to receive messages from other participants.
        """
        self.pbk = pbk
        self.pvk = pvk
        self.n = n
        self.t = t
        self.k = k
        self.my_id = my_id
        self.field = GF(Subgroup.BLS12_381)
        
        global logger 
        logfile = f'./log/logs-{self.my_id}.log'
        logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='a'
        )        
        
        self.send, self.recv = send, recv
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send

        # Initialize other required components
        self.check = True
        self.triples = []
        self.pending_1 = None
        self.pending_2 = None
        self.round = None
        self.tofallback = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        return self
    
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
        except Exception:
            logging.info("dual mode task finished")  
    
    async def handle_fallback(self, recv):
        # Listen for "timer expired" message from other participants
        while True:
            _, msg = await recv()
            if msg == "Timer expired" or "Check failed": 
                self.tofallback = True
                logger.info(f'[{self.my_id}] Starting tcv-BA')
                
                start_time = time.time()
                inputq = asyncio.Queue()
                outputq = asyncio.Queue()
                crecv_task, ba_task = await self._setup_tcvba(inputq, outputq)
                inputq.put_nowait(self.round-1)
                logger.info(f'[{self.my_id}] proposal: {self.round-1}')
                await ba_task
                ba_value = await outputq.get()

                logger.info(f'[{self.my_id}] tcv-BA finished! agreed round: {ba_value}, time:{time.time()-start_time} (seconds)')
                
                crecv_task.cancel()
                return ba_value
                
        
    
    async def _setup_tcvba(self, inputq, outputq):
        sid_c = "sid_coin"
        sid_ba = "sid_ba"
        send_c, recv_c = self.get_send(sid_c), self.subscribe_recv(sid_c)

        def bcast_c(o):
            for i in range(self.n):
                send_c(i, o)

        coin, crecv_task = await shared_coin(
            sid_c, self.my_id, self.n, self.t, self.pbk, self.pvk, bcast_c, recv_c
        )
        
        send_ba, recv_ba = self.get_send(sid_ba), self.subscribe_recv(sid_ba)

        def bcast_ba(o):
            for i in range(self.n):
                send_ba(i, o)

        ba_task = binaryagreement(
            sid_ba,
            self.my_id,
            self.n,
            self.t,
            coin,
            inputq.get,
            outputq.put_nowait,
            bcast_ba,
            recv_ba,
        )
      
        return crecv_task, ba_task
                
    async def run_dualmode(self, node_communicator):
        logger.info(f'[{self.my_id}] start OptRanTriGen')
        start_opt_time = time.time()
        send_fallback, recv_fallback = self.get_send("fallback"), self.subscribe_recv("fallback")
        def bcast(o):
            for i in range(self.n):
                send_fallback(i, o)
        
        fallback_task = asyncio.create_task(self.handle_fallback(recv_fallback))
        self.round = 1
        while True:
            logger.info(f'[{self.my_id}] start {self.round}-th OptRanTriGen instance')
            send, recv = self.get_send(str(self.round)+"-opt"), self.subscribe_recv(str(self.round)+"-opt")
            start_round_time = time.time()
            try:
                # set timer as 30 seconds 
                # currently we set 30 sec as the fallback parameter. However, in a realistic network, 
                # one needs estimate a timing parameter suitable for normally completing one round OptRanTriGen task
                # with specific nodes number and batchsize.
                triples = await asyncio.wait_for(OptRanTriGen(self.n, self.t, 
                self.k, self.my_id, send, recv, self.field, self.round, bcast=bcast, dual_mode=True), 30)                 
                if self.pending_2 is not None:
                    self.triples.append(self.pending_2)
                    logger.info(f'[{self.my_id}] output {self.round -2}-th triples')
                self.pending_2 = self.pending_1
                self.pending_1 = triples
                
            except asyncio.TimeoutError:
                self.tofallback = True
                bcast("Timer expired")
            
            if not self.tofallback:
                logger.info(f'[{self.my_id}] finished {self.round}-th OptRanTriGen instance, time: {time.time()-start_round_time}')
                self.round += 1
                continue
            else:
                R = await fallback_task
                # if R = r: output Pending_2 and Pending_1
                if R == self.round:
                    self.triples.append(self.pending_2)
                    self.triples.append(self.pending_1)
                # if R = r−1: output Pending_2 and discard Pending_1
                if R == self.round-1:
                    self.triples.append(self.pending_2)
                # if R = r−2: discard Pending_2 and Pending_1
                if R == self.round-2:
                    pass
                break
                 
        bytes_sent = node_communicator.bytes_sent
        if len(self.triples)== 1 and self.triples[0] == None:
            triple_number = 0
        else:
            triple_number = len(self.triples) * self.k
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        logger.info(f'[{self.my_id}] OptRanTriGen finished! triples: {triple_number}, time: {time.time()-start_opt_time} (seconds)')
        
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'w') as f:
                for sublist in byte_data:
                    for item in sublist:
                        f.write(str(item) + '\n')
        
        # logger.info(f"[{self.my_id}] Total bytes sent out aa: {self.triples}")
        write_bytes_to_file(f'./triples/{self.my_id}_triples.txt', self.triples)
        
        
        # switch to execute the AsyRanTriGen instance
        import subprocess
        shell_script_path = "./scripts/run_beaver.sh"
        params = [shell_script_path, str(self.n) , str(self.k) , str(self.my_id)]
        subprocess.run(params, check=True)
        
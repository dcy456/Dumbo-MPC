import logging
import asyncio
from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.hbacss import Hbacss1
import time
from ctypes import *
import json, random

lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p

lib.pyRandomShareCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyRandomShareCompute.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

class BeaverMsgType:
    ACSS1 = "R_A"
    ACSS2 = "B_A"
    ACS1 = "ACS1"
    qtrbc = "qtrbc"
    ACS2 = "ACS2"
    
class BEAVER:
    def __init__(self, public_keys,  private_key, pkbls, skbls, n, t, srs, my_id, send, recv, matrices, batchsize):
        global logger 
        logfile = f'./log/logs-{my_id}.log'

        logging.basicConfig(
            level=logging.INFO,
            # level=logging.DEBUG,
            format = '%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='a'
        )
    
        logger= logging.getLogger(__name__)
        
        self.public_keys, self.private_key, self.pkbls, self.skbls = (public_keys, private_key, pkbls, skbls)
        self.n, self.t, self.srs, self.my_id = (n, t, srs, my_id)
        self.send, self.recv = (send, recv)
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrices
        self.batchsize = batchsize

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()
        
    def __enter__(self):
        return self    
        
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("Beaver task finished")
        

    def __exit__(self, type, value, traceback):
        return self
    
    def genrandomshare(self, acsset, acss_outputs):
        acsset_list = list(acsset)
        acsset_list.sort()
        serialized_acsset = json.dumps(acsset_list).encode('utf-8')
    
        commitment = [None] * self.n
        proofsandshares = [None] * self.n
        for i in acsset:
            commitment[i] = json.loads(acss_outputs[i]['commits'].decode('utf-8'))
            proofsandshares[i] = json.loads(acss_outputs[i]['shares'].decode('utf-8'))
        
        # verification random shares
        
        # for i in range(self.n):
        #     if i in acsset_list:
        #         coms = commitment[i]
        #         proofs = proofsandshares[i]
        #         ser_coms = json.dumps(coms).encode('utf-8')
        #         ser_proofs = json.dumps(proofs).encode('utf-8')
                
        #         logger.info(f"verificaiton of outputs from {i}: {lib.pyBatchVerify(self.srs['Vk'], ser_coms, ser_proofs, self.my_id)}")
        #         # logger.info(f"proofs of node {i}: {proofs}")
        
        serialized_commitments = json.dumps(commitment).encode('utf-8')
        serialized_proofandshares = json.dumps(proofsandshares).encode('utf-8')
        
        return lib.pyRandomShareCompute(self.matrix, serialized_acsset, 
                                        serialized_commitments, serialized_proofandshares, self.t)

    async def acss_step(self, msgmode, outputs, values, acss_signal):
        
        acsstag = BeaverMsgType.ACSS1
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        if msgmode == "avss_with_proof":
            deser_comsandproofs = json.loads(values.decode('utf-8'))
            com_ab = json.dumps(deser_comsandproofs['commitment']).encode('utf-8')
        self.acss = Hbacss1(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, dealer_id=i))
        
        while True:            
            try:
                (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                pass 
            except Exception:
                pass
            except:
                pass
                
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()
            await asyncio.sleep(0.01)

            if len(outputs) == self.n:
                return
    
    
    async def run_beaver(self, node_communicator):
        logger.info(f"[{self.my_id}] Starting AsyRanShGen")
        acss_outputs = {}
        acss_signal = asyncio.Event()        
        start_time = time.time()
        values = lib.pySampleSecret(self.batchsize)

        logger.info(f"[{self.my_id}] [random shares] Starting ACSS to share {self.batchsize} secrets")
        self.acss_task = asyncio.create_task(self.acss_step("avss_without_proof", acss_outputs, values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        ACSS_Endtime = time.time() - start_time
        logger.info(f"[{self.my_id}] [random shares] ACSS time {ACSS_Endtime} seconds")

        key_proposal = list(acss_outputs.keys())
        
        acstag = BeaverMsgType.ACS1
        acssend, acsrecv = self.get_send(acstag), self.subscribe_recv(acstag)
             
        leader = 1
        logger.info(f"[{self.my_id}] [random shares] Starting ACS where node {leader} is set as leader")
        logger.info(f"[{self.my_id}] [random shares] The proposal is {key_proposal}")
        
        ACS_StartTime = time.time()
        acs = OptimalCommonSet(
            acstag,
            self.my_id,
            self.n,
            self.t,
            leader,
            key_proposal,
            self.pkbls,
            self.skbls,
            acssend, 
            acsrecv,
            acss_outputs,
            acss_signal
        )
        acsset = await acs.handle_message()

        logger.info(f"[{self.my_id}] [random shares] The ACS set is {acsset}")
        ACS_Endtime = time.time() - ACS_StartTime
        logger.info(f"[{self.my_id}] [random shares] ACS time: {ACS_Endtime} seconds")
        
        logger.info(f"[{self.my_id}] [random shares] Starting compute random shares") 
        randomsshare_StartTime = time.time()
        randomshares_proofs = self.genrandomshare(acsset, acss_outputs)
        randomsshare_Endtime = time.time() - randomsshare_StartTime
        logger.info(f"[{self.my_id}] [random shares] Random extraction time: {randomsshare_Endtime} seconds") 
        end_time = time.time() -start_time
        
        
        # The time it takes to write the random shares to the file is not included in the total time overhead
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)
        
        write_bytes_to_file(f'ransh/{self.my_id}_randomshares.txt', randomshares_proofs)
        
        
        logger.info(f"[{self.my_id}] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize) }, time: {end_time} (seconds)")
        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        
        
        acss_outputs = [None]
        randomshares_proofs = [None]
        while True:
            await asyncio.sleep(2)
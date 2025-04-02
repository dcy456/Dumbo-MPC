import logging
import asyncio
from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.hbacss import Hbacss1
import time
from ctypes import *
import json



lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

lib.pyTriplesCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyTriplesCompute.restype = c_char_p

class BeaverMsgType:
    ACSS1 = "R_A"
    ACSS2 = "B_A"
    ACS1 = "ACS1"
    ACS2 = "ACS2"
    
class BEAVER:
    def __init__(self, public_keys,  private_key, pkbls, skbls, n, t, srs, my_id, send, recv, matrices, batchsize):
        global logger 
        logfile = f'./log/logs-{my_id}.log'

        logging.basicConfig(
            level=logging.INFO,
            format = '%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='w'
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
    
    def beavergen(self, acsset, acss_outputs, sharesproofs_ab):
        acsset_list = list(acsset)
        acsset_list.sort()
        serialized_acsset = json.dumps(acsset_list).encode('utf-8')
    
        commitment = [None] * self.n
        proofsandshares = [None] * self.n
        for i in acsset:
            commitment[i] = json.loads(acss_outputs[i]['commits'].decode('utf-8'))
            proofsandshares[i] = json.loads(acss_outputs[i]['shares'].decode('utf-8'))

        filtered_commitments = [item for item in commitment if item is not None ]
        filtered_proofandshares = [item for item in proofsandshares if item is not None ]
        serialized_commitments = json.dumps(filtered_commitments).encode('utf-8')
        serialized_proofandshares = json.dumps(filtered_proofandshares).encode('utf-8')


        deserialized_commandprooflist = json.loads(sharesproofs_ab.decode('utf-8')) 
        serialized_share_ab = json.dumps(deserialized_commandprooflist["proof"]).encode('utf-8')
        
        serialized_triples = lib.pyTriplesCompute(serialized_acsset, serialized_share_ab, serialized_proofandshares, serialized_commitments)
        
        return serialized_triples   

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
    
    async def reduction(self, msgmode, outputs, values, acss_signal):
        
        acsstag = BeaverMsgType.ACSS2
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
        logger.info(f"[{self.my_id}] Starting AsyRanTriGen") 
        with open(f'ransh/{self.my_id}_randomshares.txt', 'rb') as file:
            reduction_values = file.read()        

        start_time = time.time()
        reduction_outputs = {}
        reduction_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(self.reduction("avss_with_proof", reduction_outputs, reduction_values, reduction_signal))
        await reduction_signal.wait()
        reduction_signal.clear()
        acss_time = time.time() - start_time
        logger.info(f"[{self.my_id}] [triple] ACSS time {acss_time} seconds")

        reduction_proposal = list(reduction_outputs.keys())
        
        acstag_beaver = BeaverMsgType.ACS2 # (R, msg)
        acssend, acsrecv = self.get_send(acstag_beaver), self.subscribe_recv(acstag_beaver)
        leader = 2
        logger.info(f"[triple] Starting to ACS where {leader} is set as leader ")

        ACS_Starttime = time.time()
        logger.info(f"[triple] The proposal is {reduction_proposal}")                
        acs = OptimalCommonSet(
            acstag_beaver,
            self.my_id,
            self.n,
            self.t,
            leader,
            reduction_proposal,
            self.pkbls,
            self.skbls,
            acssend, 
            acsrecv,
            reduction_outputs,
            reduction_signal
        )
        acsset_beaver = await acs.handle_message()
        logger.info(f"[triple] The ACS set is {acsset_beaver}")
        ACS_EndTime = time.time()- ACS_Starttime
        logger.info(f"[{self.my_id}] [triple] ACS time: {ACS_EndTime} seconds")
        
        Triple_Statrtime = time.time()
        triples = self.beavergen(acsset_beaver, reduction_outputs, reduction_values)
        Triple_EndTime = time.time()- Triple_Statrtime
        logger.info(f"[{self.my_id}] [triple] Triple computation time: {Triple_EndTime} seconds")
                
        reduction_outputs = [None]
        end_time = time.time() -start_time
        
        # The time it takes to write the triples to the file is not included in the total time overhead
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)
        
        write_bytes_to_file(f'triples/{self.my_id}_triples.txt', triples)
        
        
        logger.info(f"[triple] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {end_time} (seconds)")
        
        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
            logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")

        
        triples = [None]
        while True:
            await asyncio.sleep(2)
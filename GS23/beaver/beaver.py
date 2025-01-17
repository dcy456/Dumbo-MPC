import logging
import asyncio
from beaver.broadcast.optacs import optimalcommonset
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.hbacss import Hbacss1
import time
from ctypes import *
import json, gc



lib = CDLL("./pedersen_out.so")
lib.pyPedSampleSecret.argtypes = [c_int]
lib.pyPedSampleSecret.restype = c_char_p

lib.pyPedRandomShareComputeWithoutRanExt.argtypes = [c_char_p, c_char_p]
lib.pyPedRandomShareComputeWithoutRanExt.restype = c_char_p

lib.pyPedBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyPedBatchVerify.restype = c_bool

lib.pyPedTriplesCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyPedTriplesCompute.restype = c_char_p



class BeaverMsgType:
    ACSS1 = "R_A"
    ACSS2 = "B_A"
    ACS1 = "ACS1"
    ACS2 = "ACS2"
    
class BEAVER:
    def __init__(self, public_keys,  private_key, pkbls, skbls, n, t, srs, my_id, send, recv, matrices, batchsize):
        self.public_keys, self.private_key, self.pkbls, self.skbls = (public_keys, private_key, pkbls, skbls)
        global logger 
        logfile = f'./log/logs-{my_id}.log'
        logging.basicConfig(
            level=logging.INFO,
            # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            format = '%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='a'
        )
    
        logger= logging.getLogger(__name__)
        
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

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
        
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
        shares = [None] * self.n
        for i in acsset:
            commitment[i] = json.loads(acss_outputs[i]['commits'].decode('utf-8'))
            shares[i] = json.loads(acss_outputs[i]['shares'].decode('utf-8'))

        filtered_commitments = [item for item in commitment if item is not None ]
        filtered_shares = [item for item in shares if item is not None ]
        serialized_commitments = json.dumps(filtered_commitments).encode('utf-8')
        serialized_shares = json.dumps(filtered_shares).encode('utf-8')
        # # verification random shares
        randomshares_proofs = lib.pyPedRandomShareComputeWithoutRanExt(serialized_commitments, serialized_shares)
        
        return randomshares_proofs

    async def acss_step(self, msgmode, outputs, values, acss_signal):
        
        acsstag = BeaverMsgType.ACSS1
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        if msgmode == "avss_with_proof":
            deser_comsandproofs = json.loads(values.decode('utf-8'))
            com_ab = json.dumps(deser_comsandproofs['commitment']).encode('utf-8')
            deser_comsandproofs = None
            del deser_comsandproofs
            gc.collect

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
            if len(outputs) >= self.t + 1:
                acss_signal.set()
            await asyncio.sleep(0.01)

            # if len(outputs) == self.n:
            #     com_ab = None
            #     outputs = None
            #     del outputs, com_ab
            #     gc.collect
            #     return
    
    def beavergen(self, acsset, acss_outputs, comshares_ab):
        acsset_list = list(acsset)
        acsset_list.sort()
        serialized_acsset = json.dumps(acsset_list).encode('utf-8')
    
        commitment = [None] * self.n
        shares = [None] * self.n
        for i in acsset:
            commitment[i] = json.loads(acss_outputs[i]['commits'].decode('utf-8'))
            shares[i] = json.loads(acss_outputs[i]['shares'].decode('utf-8'))

        
        filtered_commitments = [item for item in commitment if item is not None ]
        filtered_shares = [item for item in shares if item is not None ]
        serialized_commitments = json.dumps(filtered_commitments).encode('utf-8')
        serialized_shares = json.dumps(filtered_shares).encode('utf-8')

        
        deserialized_commandsharelist = json.loads(comshares_ab.decode('utf-8'))
        serialized_shares_ab = json.dumps(deserialized_commandsharelist["share"]).encode('utf-8')
        
        serialized_com_triples = lib.pyPedTriplesCompute(serialized_acsset, serialized_shares_ab, serialized_shares, serialized_commitments)
        
        deserialized_Com_Triples= json.loads(serialized_com_triples.decode('utf-8'))
        serialized_triples = json.dumps(deserialized_Com_Triples['Triples']).encode('utf-8')  
         
        return serialized_triples  
    
    async def reduction(self, msgmode, outputs, values, acss_signal):
        
        acsstag = BeaverMsgType.ACSS2
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        if msgmode == "avss_with_proof":
            deser_comsandshares = json.loads(values.decode('utf-8'))
            com_ab = json.dumps(deser_comsandshares['commitment']).encode('utf-8')
            # deser_comsandproofs = None
            # del deser_comsandproofs
            # gc.collect
            
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
            # logger.info(f"[{self.my_id}] dealer:{dealer}")
            if len(outputs) >= self.n - self.t:
                # logger.info(f"[{self.my_id}] >2t")
                acss_signal.set()
            # await asyncio.sleep(0.01)

            if len(outputs) == self.n:
                # outputs = None
                # del outputs
                # gc.collect

                return
    
    
    async def run_beaver(self, node_communicator):
        logger.info(f"[{self.my_id}] Starting random share generation")
        start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()        
        msgmode = "avss_without_proof"
        values = lib.pyPedSampleSecret(self.batchsize)

        logger.info(f"[{self.my_id}] Starting ACSS to share {self.batchsize} secrets")
        self.acss_task = asyncio.create_task(self.acss_step(msgmode, acss_outputs, values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()

        key_proposal = list(acss_outputs.keys())        
        
        acstag = BeaverMsgType.ACS1
        acssend, acsrecv = self.get_send(acstag), self.subscribe_recv(acstag)
        leader = 1
        
        logger.info(f"[{self.my_id}] [random shares] Starting ACS where node {leader} is set as leader ")
        logger.info(f"[{self.my_id}] [random shares] The proposal is {key_proposal}")
        acstask = asyncio.create_task(
            optimalcommonset(
                acstag,
                self.my_id,
                self.n,
                self.t,
                leader,
                key_proposal,
                self.pkbls,
                self.skbls,
                acsrecv,
                acssend,
                acss_outputs,
                acss_signal,
            )
        )
        acsset = await acstask
        logger.info(f"[{self.my_id}] [random shares] The ACS set is {acsset}")


        logger.info(f"[{self.my_id}] Starting compute random shares") 
        reduction_values = self.genrandomshare(acsset, acss_outputs)

        logger.info(f"[{self.my_id}] random share generation finished! Total number: {int (self.batchsize) }")
        
        # acss_outputs = [None]
        # randomshares_proofs = [None]
        # del acss_outputs, randomshares_proofs
        # gc.collect     

        msgmode = "avss_with_proof"
        reduction_outputs = {}
        reduction_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(self.reduction(msgmode, reduction_outputs, reduction_values, reduction_signal))
        await reduction_signal.wait()
        reduction_signal.clear()

        reduction_proposal = list(reduction_outputs.keys())
        
        acstag_beaver = BeaverMsgType.ACS2 # (R, msg)
        acssend, acsrecv = self.get_send(acstag_beaver), self.subscribe_recv(acstag_beaver)
        leader = 2
        logger.info(f"[{self.my_id}] [triples] Starting to ACS where {leader} is set as leader ")

        logger.info(f"[{self.my_id}] [triples] The proposal is {reduction_proposal}")                

        acstask = asyncio.create_task(
            optimalcommonset(
                acstag_beaver,
                self.my_id,
                self.n,
                self.t,
                leader,
                reduction_proposal,
                self.pkbls,
                self.skbls,
                acsrecv,
                acssend,
                reduction_outputs,
                reduction_signal,
            )
        )
        acsset_beaver = await acstask
        logger.info(f"[{self.my_id}] [triples] The ACS set is {acsset_beaver}")

        triples = self.beavergen(acsset_beaver, reduction_outputs, reduction_values)

        end_time = time.time() - start_time

        reduction_outputs = [None]
        del reduction_outputs
        gc.collect
        
        logger.info(f"Triple generation finished! Total number: {int (self.batchsize / 2) }, time: {end_time} (seconds)")
        
        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")

        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)
        
        write_bytes_to_file(f'triples/{self.my_id}_triples.txt', triples)
        
        triples = [None]

        while True:
            await asyncio.sleep(2)
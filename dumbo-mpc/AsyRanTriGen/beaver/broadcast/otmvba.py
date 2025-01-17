# coding=utf-8
from collections import defaultdict
import zfec
import logging
import hashlib
import math
from pickle import dumps, loads
from beaver.broadcast.crypto.boldyreva import serialize, deserialize1
from beaver.broadcast.optqrbc import optqrbc
from beaver.utils.bitmap import Bitmap
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.broadcast.binaryagreement import binaryagreement
from beaver.broadcast.commoncoin import shared_coin
from ctypes import *
import json
import asyncio



logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)

class OptimalCommonSet:
    def __init__(self, sid, pid, n, f, leader, input, pk, sk, send, receive, acss_outputs, acss_signal):
        """
        Initialize the OptimalCommonSet class.
        """
        # Initialize input parameters
        self.sid = sid
        self.pid = pid
        self.n = n
        self.f = f
        self.leader = leader
        self.input = sorted(input)
        self.pk = pk
        self.sk = sk
        self.acss_outputs = acss_outputs
        self.acss_signal = acss_signal

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(receive)
        
        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send

        # Initialize protocol state variables
        self.received = defaultdict(dict)
        self.fallback_messages = []
        self.leaderProposal = None
        self.received_vote_qc = False
        self.received_prevoteQC = False
        self.leader_received = False
        self.SIGMA1 = None
        self.SIGMA2 = None
        
        #// TODO: currently we set either 0 or 100 sec as the timeout parameter, 
        # as the former one always trigger otMVBA's fallback and the latter always 
        # waits for the fastpath to return. However, in a realistic network, 
        # one needs estimate a timing parameter suitable for the normal network latency.
        self.FALLBACK_TIMEOUT = 100  # seconds

    async def fallback_timer(self, broadcast):
        """
        Start a fallback timeout timer to ensure fallback path is triggered if needed.
        """
        await asyncio.sleep(self.FALLBACK_TIMEOUT)
        if not self.received_vote_qc:
            # logging.info(f"[{self.pid}] Timeout reached, no valid VoteQC received. Entering fallback path.")
            if self.received_prevoteQC:
                # If PrevoteQC is received, send "leader" type fallback message
                broadcast((self.sid, "Fallback", self.pid, "leader", self.leaderProposal, serialize(self.SIGMA1)))
                # logging.info(f"[{self.pid}] Sending fallback message with prevoteQC")
            else:
                # Otherwise, send "non-leader" type fallback message
                sigma0 = self.sk.sign(self.pk.hash_message(str((self.sid, "no QC received"))))
                broadcast((self.sid, "Fallback", self.pid, "non-leader", None, serialize(sigma0)))
                # logging.info(f"[{self.pid}] Sending fallback message with no QC received")

    async def handle_message(self):
        """
        Main message handling logic.
        """
        
        optsend, optrecv =  self.get_send(self.sid), self.subscribe_recv(self.sid)
        def broadcast(o):
            for i in range(self.n):
                optsend(i, o)
        
        # If the current node is the leader, broadcast its input
        if self.pid == self.leader:
            
            # Stuck here to trigger the fallback path with party's own input 
            # await asyncio.sleep(5)
            broadcast((self.sid, "value", self.input))

        # Start the fallback timer
        asyncio.create_task(self.fallback_timer(broadcast))

        # Message loop
        while True:
            sender, msg = await optrecv()
            logging.debug(f"[{self.pid}] msg {msg[1]}")
            # Handle different message types
            if msg[1] == "value":
                await self.handle_value_message(msg, optsend)
            elif msg[1] == "prevote":
                await self.handle_prevote_message(msg, broadcast)
            elif msg[1] == "PrevoteQC":
                await self.handle_prevote_qc_message(msg, optsend)
            elif msg[1] == "vote":
                await self.handle_vote_message(msg, broadcast)
            elif msg[1] == "VoteQC":
                await self.handle_vote_qc_message(msg, broadcast)
            elif msg[1] == "Terminate":
                result = await self.handle_terminate_message(msg, broadcast)
                return result
            elif msg[1] == "Fallback":
                relult = await self.handle_fallback_message(msg)
                if relult is not None:
                    return relult

    async def handle_value_message(self, msg, send):
        """
        Handle "value" type message.
        """
            
        while True:
            logging.debug(f"[{self.pid}] value-self.acss_outputs.keys():{self.acss_outputs.keys()}")
            subset = True
            for item in msg[2]:
                if item not in self.acss_outputs.keys():
                    subset = False
            if subset:
                self.acss_signal.clear()
                sigma1 = self.sk.sign(self.pk.hash_message(str((self.sid, "prevote", msg[2]))))
                send(self.leader, (self.sid, "prevote", self.pid, serialize(sigma1)))
                self.leaderProposal = msg[2]
                break
            self.acss_signal.clear()
            await self.acss_signal.wait()
                
            # if set(msg[2]).issubset(list(self.acss_outputs.keys())):
            #     sigma1 = self.sk.sign(self.pk.hash_message(str((self.sid, "prevote", msg[2]))))
            #     send(self.leader, (self.sid, "prevote", self.pid, serialize(sigma1)))
            #     self.leaderProposal = msg[2]
            #     # logging.info("[{self.pid}] --Directly send the proposal!--")
            #     break
            # else:
            #     # self.acss_signal.clear()
            #     await self.acss_signal.wait()
            #     if set(msg[2]).issubset(list(self.acss_outputs.keys())):
            #         logging.info(f"[{self.pid}] Wait for the proposal!")
            #         self.acss_signal.clear()

    async def handle_prevote_message(self, msg, broadcast):
        """
        Only leader handles "prevote" type message.
        """
        sig_share = deserialize1(msg[3])
        h = self.pk.hash_message(str((self.sid, "prevote", self.input)))
        try:
            self.pk.verify_share(sig_share, msg[2], h)
        except AssertionError:
            logging.info(f"[{self.pid}] Signature share failed! {(self.sid, self.leader, msg[2], msg[1], self.input)}")
            return

        self.received['prevote'][msg[2]] = sig_share

        if len(self.received['prevote']) == 2 * self.f + 1:
            sigs = dict(list(self.received['prevote'].items())[: self.f + 1])
            self.SIGMA1 = self.pk.combine_shares(sigs)
            assert self.pk.verify_signature(self.SIGMA1, h)
            broadcast((self.sid, "PrevoteQC", self.input, serialize(self.SIGMA1)))

    async def handle_prevote_qc_message(self, msg, send):
        """
        Handle "PrevoteQC" type message.
        """
        self.SIGMA1 = deserialize1(msg[3])
        h = self.pk.hash_message(str((self.sid, "prevote", msg[2])))
        assert self.pk.verify_signature(self.SIGMA1, h)
        sigma2 = self.sk.sign(self.pk.hash_message(str((self.sid, "vote", msg[2]))))
        send(self.leader, (self.sid, "vote", self.pid, serialize(sigma2)))
        self.received_prevoteQC = True

    async def handle_vote_message(self, msg, broadcast):
        """
        Handle "vote" type message.
        """
        sig_share = deserialize1(msg[3])
        h = self.pk.hash_message(str((self.sid, "vote", self.input)))
        try:
            self.pk.verify_share(sig_share, msg[2], h)
        except AssertionError:
            logger.error(f"Signature share failed! {(self.sid, self.pid, msg[2], msg[1])}")
            return

        self.received['vote'][msg[2]] = sig_share

        if len(self.received['vote']) == 2 * self.f + 1:
            sigs = dict(list(self.received['vote'].items())[: self.f + 1])
            self.SIGMA2 = self.pk.combine_shares(sigs)
            assert self.pk.verify_signature(self.SIGMA2, h)
            
            # Stuck here to triger the fallback path with the received proposal of leader
            # await asyncio.sleep(5)
            broadcast((self.sid, "VoteQC", self.input, serialize(self.SIGMA2)))

    async def handle_vote_qc_message(self, msg, broadcast):
        """
        Handle "VoteQC" type message.
        """
        self.SIGMA2 = deserialize1(msg[3])
        h = self.pk.hash_message(str((self.sid, "vote", msg[2])))
        assert self.pk.verify_signature(self.SIGMA2, h)

        broadcast((self.sid, "Terminate", msg[2], serialize(self.SIGMA2)))
        self.received_vote_qc = True
    
    async def handle_terminate_message(self, msg, broadcast):
        """
        Handle "Terminate" type message.
        """
        SIGMA2 = deserialize1(msg[3])
        h = self.pk.hash_message(str((self.sid, "vote", msg[2])))
        assert self.pk.verify_signature(SIGMA2, h)
        
        while True:
            logging.debug(f"[{self.pid}] self.acss_outputs.keys():{self.acss_outputs.keys()}")
            subset = True
            for item in msg[2]:
                if item not in self.acss_outputs.keys():
                    subset = False
            if subset:
                self.acss_signal.clear()
                broadcast((self.sid, "Terminate", msg[2], serialize(SIGMA2)))
                return msg[2]
            self.acss_signal.clear()
            await self.acss_signal.wait()
        

        # broadcast((self.sid, "Terminate", msg[2], serialize(SIGMA2)))
        # return msg[2]
        
    async def handle_fallback_message(self, msg):
        """
        Handle "Fallback" type message.
        """
        if msg[3] == "leader":
            # logging.info(f"[{self.pid}] Received fallback message of leader")
            sig = deserialize1(msg[5])
            h = self.pk.hash_message(str((self.sid, "prevote", msg[4])))
            assert self.pk.verify_signature(sig, h)
            self.leader_received = True
            inputwithleadermsg = ('leader', msg[4], serialize(sig))
            self.fallback_messages.append(msg)
        elif msg[3] == "non-leader":
            # logging.info(f"[{self.pid}] Received fallback message of non-leader")
            assert msg[2] in range(self.n)
            sig_share = deserialize1(msg[5])
            h = self.pk.hash_message(str((self.sid, "no QC received")))
            try:
                self.pk.verify_share(sig_share, msg[2], h)
                self.received['non-leader'][msg[2]] = sig_share
                self.fallback_messages.append(msg)
            except AssertionError:
                logging.info(f"[{self.pid}] Signature share failed! {(self.sid, self.pid, msg[2])}")
                return
            
        # Wait for n - f distinct fallback messages
        if len(self.fallback_messages) == self.n - self.f:
            logging.info(f"[{self.pid}] receivied {self.n - self.f} distinct fallback messages")
            if self.leader_received:
                logging.info(f"[{self.pid}] Received valid 'pre-vote QC' type in fallback messages")
                # Call the underlying MVBA protocol
                mvba_result = await self.makeagreement(inputwithleadermsg)
                # Once MVBA protocol returns, output the result
                return mvba_result
            else:
                logging.info(f"[{self.pid}] Received 'no QC received' type in fallback messages")
                assert len(self.received['non-leader']) == self.n - self.f
                sigs = dict(list(self.received['non-leader'].items())[: self.f + 1])
                SIGMA0 = self.pk.combine_shares(sigs)
                # Call the underlying MVBA protocol 
                mvba_result = await self.makeagreement(('non-leader', self.input, serialize(SIGMA0)))

                # Once MVBA protocol returns, output the result
                return mvba_result
            
    async def makeagreement(self, input):
        create_acs_task = asyncio.create_task(self.agreement(input, self.acss_outputs, self.acss_signal))
        acs,  recv_tasks, work_tasks = await create_acs_task
        acsoutput = await acs
        
        await asyncio.gather(*work_tasks)
        for task in recv_tasks:
            task.cancel()
        return acsoutput
        
    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_values, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            _, _, rbc_bitmap= loads(rbcl)
            rbcb = Bitmap(self.n, rbc_bitmap)
            rbc_values[j] = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
                    
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            logger.debug(f'[{self.pid}] rbc_values: {acss_outputs.keys()}')
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range (self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        # rbc_signal.set()
        mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                mks = mks.union(set(list(ks)))
                if len(mks) >= self.n-self.f:
                    break
                
        # Waiting for all ACSS to terminate
        for k in mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()
        return mks
        
    # TODO replace the ACS with MVBA
    async def agreement(self, input, acss_outputs, acss_signal):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        flag, key_proposal, sig = input

        async def predicate(_input):
            _flag, sig, _key_proposal  = loads(_input)
            
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            if len(kpl) <= self.f:
                return False
            
            if _flag == 'leader':
                test = self.pk.verify_signature(deserialize1(sig), self.pk.hash_message(str((self.sid, "prevote", kpl))))
                if not self.pk.verify_signature(deserialize1(sig), self.pk.hash_message(str((self.sid, "prevote", kpl)))):
                    return False
            if _flag == 'non-leader':
                if not self.pk.verify_signature(deserialize1(sig), self.pk.hash_message(str((self.sid, "no QC received")))):
                    return False
                
            logging.debug(f'[{self.pid}] predicate: {kpl}, acss_outputs.keys():{acss_outputs.keys()}')
            while True:
                logging.debug(f'[{self.pid}] acss_outputs.keys():{acss_outputs.keys()}')
                subset = True
                for kk in kpl:
                    if kk not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()   
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            
            # starting RBC
            rbctag ="RBC" + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            _rbc_input = [flag, sig]
            if j == self.pid: 
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                _rbc_input.append(bytes(riv.array))
            rbc_input = dumps(_rbc_input)
            # rbc_outputs[j] = 
            asyncio.create_task(
                optqrbc(
                    rbctag,
                    self.pid,
                    self.n,
                    self.f,
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                )
            )
            abatag = "B" + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(self.n):
                    abasend(i, o)
            
            cointag = "coin" + str(j) # (B, msg)
            # abatag = j # (B, msg)
            coinsend, coinrecv =  self.get_send(cointag), self.subscribe_recv(cointag)
            
            def coin_bcast(o):
                 for i in range(self.n):
                    coinsend(i, o)

            coin, coin_recv_task = await shared_coin(
                self.sid + "COIN" + str(j), self.pid, self.n, self.f, self.pk, self.sk, coin_bcast, coinrecv
            )
            aba_task = asyncio.create_task(
                binaryagreement(
                    abatag,
                    self.pid,
                    self.n,
                    self.f,
                    coin,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
        
            return coin_recv_task, aba_task

        returned_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        work_tasks = []
        recv_tasks = []
        for c_task, rcv_task in returned_tasks:
            recv_tasks.append(c_task)
            work_tasks.append(rcv_task)
            
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_values,
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            recv_tasks,
            work_tasks,
        )
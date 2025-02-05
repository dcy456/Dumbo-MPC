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
        
        self.send, self.recv = (send, recv)
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
    
    async def _recv_loop(self, recv, s=0):
        results = [None] * self.n
        for _ in range(self.n):
            sender_id, value = await recv()
            results[sender_id - s] = value
        return results

    async def randousha(self, k):
        """
        Generates a batch of (n-2t)k secret sharings of random elements
        """            
        poly = polynomials_over(self.field)
        eval_point = EvalPoint(self.field, self.n, use_omega_powers=False)
        big_t = self.n - (2 * self.t) - 1  # This is same as `T` in the HyperMPC paper.
        encoder = EncoderFactory.get(eval_point)
        

        # Pick k random elements
        def to_int(coeffs):
            return tuple(map(int, coeffs))
            
        my_randoms = [self.field.random() for _ in range(k)]
        
        # Generate t and 2t shares of the random element.
        coeffs_t = [to_int(poly.random(self.t, r).coeffs) for r in my_randoms]
        coeffs_2t = [to_int(poly.random(2 * self.t, r).coeffs) for r in my_randoms]
        unref_t = encoder.encode(coeffs_t)    
        unref_2t = encoder.encode(coeffs_2t)

        # Start listening for my share of t and 2t shares from all parties.
        send, recv = self.get_send(str(self.round)+"H1"), self.subscribe_recv(str(self.round)+ "H1")
        share_recv_task = asyncio.create_task(self._recv_loop(recv))

        # Send each party their shares.
        to_send_t = transpose_lists(unref_t)
        to_send_2t = transpose_lists(unref_2t)
        for i in range(self.n):
            send(i, (to_send_t[i], to_send_2t[i]))

        # Wait until all shares are received.
        received_shares = await share_recv_task
        unrefined_t_shares, unrefined_2t_shares = zip(*received_shares)

        # Apply the hyper-invertible matrix.
        # Assume the unrefined shares to be coefficients of a polynomial
        # and then evaluate that polynomial at powers of omega.
        ref_t = encoder.encode(transpose_lists(list(unrefined_t_shares)))
        ref_2t = encoder.encode(transpose_lists(list(unrefined_2t_shares)))

        # Parties with id in [N-2t+1, N] need to start
        # listening for shares which they have to check.
        send, recv = self.get_send(str(self.round)+"H2"), self.subscribe_recv(str(self.round)+"H2")
        # send, recv = _get_send_recv("H2")
        to_send_t = transpose_lists(ref_t)
        to_send_2t = transpose_lists(ref_2t)

        if self.my_id > big_t:
            share_chk_recv_task = asyncio.create_task(self._recv_loop(recv))

        # Send shares of parties with id in [N-2t+1, N] to those parties.
        for i in range(big_t + 1, self.n):
            send(i, (to_send_t[i], to_send_2t[i]))
        

        # Parties with id in [N-2t+1, N] need to verify that the shares are in-fact correct.
        if self.my_id > big_t:
            shares_to_check = await share_chk_recv_task
            shares_t, shares_2t = zip(*shares_to_check)
            # self.response = HyperInvMessageType.ABORT

            def get_degree(p):
                for i in range(len(p))[::-1]:
                    if p[i] != 0:
                        return i
                return 0

            def get_degree_and_secret(shares):
                decoder = DecoderFactory.get(eval_point)
                polys = decoder.decode(list(range(self.n)), transpose_lists(list(shares)))
                secrets = [p[0] for p in polys]
                degrees = [get_degree(p) for p in polys]
                return degrees, secrets

            degree_t, secret_t = get_degree_and_secret(shares_t)
            degree_2t, secret_2t = get_degree_and_secret(shares_2t)

            # Verify that the shares are in-fact `t` and `2t` shared.
            # Verify that both `t` and `2t` shares of the same value.
            if not (
                all(deg == self.t for deg in degree_t)
                and all(deg == 2 * self.t for deg in degree_2t)
                and secret_t == secret_2t
            ):
                self.check = HyperInvMessageType.ABORT
            
            # simulate check failure
            # if self.round == 10 and self.my_id > big_t:
            # logger.info(f"self.my_id:{self.my_id}")
            if self.round == 10:
                self.check = HyperInvMessageType.ABORT

            # logger.debug(
            #     "[%d] Degree check: %s, Secret Check: %s",
            #     self.my_id,
            #     all(deg == self.t for deg in degree_t)
            #     and all(deg == 2 * self.t for deg in degree_2t),
            #     secret_t == secret_2t,
            # )
        if self.my_id < big_t:
            await asyncio.sleep(0.5)

        out_t = flatten_lists([s[: big_t + 1] for s in ref_t])
        out_2t = flatten_lists([s[: big_t + 1] for s in ref_2t])

        return tuple(zip(out_t, out_2t))


    async def OptRanTriGen(self):        
        # Start listening for my share of t and 2t shares from all parties.
        send, recv = self.get_send(str(self.round)+"randousha"), self.subscribe_recv(str(self.round)+"randousha")
        rs_t2t = await self.randousha(3 * self.k)

        as_t2t = rs_t2t[0 * self.k : 1 * self.k]
        bs_t2t = rs_t2t[1 * self.k : 2 * self.k]
        rs_t2t = rs_t2t[2 * self.k : 3 * self.k]

        as_t, _ = zip(*as_t2t)
        bs_t, _ = zip(*bs_t2t)
        as_t = list(map(self.field, as_t))
        bs_t = list(map(self.field, bs_t))
        rs_t, rs_2t = zip(*rs_t2t)


        # Compute degree reduction to get triples
        # TODO: Use the mixins and preprocessing system
        async def prog(ctx):
            assert len(rs_2t) == len(rs_t) == len(as_t) == len(bs_t)

            abrs_2t = [a * b + r for a, b, r in zip(as_t, bs_t, rs_2t)]
            abrs = await ctx.ShareArray(abrs_2t, 2 * self.t).open()
            abs_t = [abr - r for abr, r in zip(abrs, rs_t)]
            return list(zip(as_t, bs_t, abs_t))

        # TODO: compute triples through degree reduction
        send, recv = self.get_send(str(self.round)+"opening"), self.subscribe_recv(str(self.round)+"opening")
        # send, recv = _get_send_recv("opening")
        ctx = Mpc(f"mpc:opening", self.n, self.t, self.my_id, send, recv, prog, {})

        result = await ctx._run()
        
        # simulate time expires
        # if self.my_id == 1 and self.round == 10:
        #     await asyncio.sleep(50)
        
        return result
      
    
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
    
    async def monitor_check_status(self, bcast):
        while True:
            await asyncio.sleep(0.5) 
            if not self.check:
                # Broadcasting the 'check failed' message to all participants
                bcast("Check failed")
                
    async def run_dualmode(self, node_communicator):
        logger.info(f'[{self.my_id}] start OptRanTriGen')
        start_opt_time = time.time()
        send, recv = self.get_send("fallback"), self.subscribe_recv("fallback")
        def bcast(o):
            for i in range(self.n):
                send(i, o) 
        asyncio.create_task(self.monitor_check_status(bcast))
        
        fallback_task = asyncio.create_task(self.handle_fallback(recv))
        self.round = 1
        while True:
            logger.info(f'[{self.my_id}] start {self.round}-th OptRanTriGen instance')
            start_round_time = time.time()
            try:
                # set timer as 30 seconds 
                # currently we set 30 sec as the fallback parameter. However, in a realistic network, 
                # one needs estimate a timing parameter suitable for normally completing one round OptRanTriGen task
                # with specific nodes number and batchsize.
                triples = await asyncio.wait_for(self.OptRanTriGen(), 30)                 
                if self.pending_2 is not None:
                    self.triples.append(self.pending_2)
                    logger.info(f'[{self.my_id}] output {self.round -2}-th triples')
                self.pending_2 = self.pending_1
                self.pending_1 = triples

                if not self.check:
                    self.tofallback = True
                    bcast("Check failed")
                
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
        